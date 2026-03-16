import connectDB from "@/connectDB/database";
import GoogleProvider from "next-auth/providers/google";
import User from "@/models/User";
import CredentialsProvider from "next-auth/providers/credentials";
import bcrypt from "bcrypt";
import { MongoDBAdapter } from "@auth/mongodb-adapter";
import clientPromise from "@/lib/db";
import { ipLimiter, accountLimiter } from "@/lib/rateLimit";

import {
  isAccountLocked,
  resetLoginAttempts,
  registerFailedAttempt,
} from "@/lib/loginLock";

export const authOptions = {
  adapter: MongoDBAdapter(clientPromise),

  session: {
    strategy: "jwt",
    maxAge: 24 * 60 * 60, // 24 hours
    updateAge: 60 * 60, // 1 hour - refresh session hourly
  },

  jwt: {
    secret: process.env.NEXTAUTH_SECRET,
    maxAge: 60 * 60 * 24, // 24 hours
  },

  cookies: {
    sessionToken: {
      name: `__Secure-next-auth.session-token`,
      options: {
        httpOnly: true,
        sameSite: "strict", // "strict" if using OAuth providers
        path: "/",
        secure: true, //in production >  process.env.NODE_ENV === "production"
      },
    },
  },

  providers: [
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      authorization: {
        params: {
          prompt: "consent",
          access_type: "offline",
          response_type: "code",
        },
      },
      allowDangerousEmailAccountLinking: true,
    }),

    CredentialsProvider({
      name: "Credentials",
      credentials: {
        email: {
          label: "Email:",
          type: "email",
          placeholder: "email",
        },
        password: {
          label: "Password:",
          type: "password",
          placeholder: "password",
        },
      },

      async authorize(credentials, req) {

        console.log("AUTHORIZE CALLED");
        try {
          if (!credentials?.email || !credentials?.password) {
            throw new Error("MISSING_CREDENTIALS");
          }

          const email = credentials.email.toLowerCase();

          const ip =
            req?.headers?.["x-forwarded-for"] ||
            req?.socket?.remoteAddress ||
            "unknown";

          const identifier = `${ip}`;

          // Check if account is locked
          const locked = await isAccountLocked(email);
          if (locked) {
            throw new Error("ACCOUNT_LOCKED");
          }

          // Rate limit
          const { success: ipSuccess } = await ipLimiter.limit(identifier);

          if (!ipSuccess) {
            throw new Error("RATE_LIMIT_IP");
          }

          const { success: accountSuccess } = await accountLimiter.limit(email);

          if (!accountSuccess) {
            throw new Error("RATE_LIMIT_ACCOUNT");
          }

          console.log("Rate limit:", { accountSuccess });

          await connectDB();

          const dbUser = await User.findOne({ email }).select("+password");

          if (!dbUser || !(await bcrypt.compare(
            credentials.password,
            dbUser.password)
          )) {
            await registerFailedAttempt(email);
            throw new Error("INVALID_CREDENTIALS");
          }

          // const match = await bcrypt.compare(
          //   credentials.password,
          //   dbUser.password,
          // );

          // if (!match) {
          //   await registerFailedAttempt(email); // ← PUT IT HERE
          //   throw new Error("INVALID_CREDENTIALS");
          // }

          // Successful login → remove lock
          await resetLoginAttempts(email);

          return {
            id: dbUser._id.toString(),
            name: dbUser.name,
            username: dbUser.username,
            email: dbUser.email,
            avatar: dbUser.avatar,
          };
        } catch (error) {
          console.error("Auth error:", error);
          throw error;
        }
      },
    }),
  ],

  callbacks: {
    //Invoked on successful signin
    async signIn({ user, profile, account }) {
      if (account.provider === "google") {
        // console.log("Google profile:", profile);
        // console.log("User:", user);

        await connectDB();

        // Find the user in your DB
        const dbUser = await User.findOne({ email: profile.email });

        // If the user doesn't exist, create it
        if (!dbUser) {
          const newUser = await User.create({
            email: profile.email,
            username: profile.given_name,
            name: profile.name,
          });
          return {
            id: newUser._id.toString(),
            name: newUser.name,
            username: newUser.username,
            email: newUser.email,
          };
        } else {
          return {
            id: user.id.toString(),
            name: user.name,
            username: user.username,
            email: user.email,
            avatar: user.avatar,
          };
        }
      }

      return true;
    },

    async jwt({ token, user, account, trigger, session }) {
      if (user) {
        token.username = user.username;
        token.id = user.id;
        token.avatar = user.avatar;
      }
      if (trigger === "update" && session?.user) {
        token.avatar = session.user.avatar;
      }

      return token;
    },

    //Modify the session object
    async session({ session, token }) {
      //  NextAuth automatically includes the name property in the session if it exists on the user object
      // Assign user id to the session
      session.user.id = token.id;
      // Assign username to the session
      session.user.username = token.username;
      // Assign avatar to the session
      session.user.avatar = token.avatar;
      // console.log("Session:", session);
      return session;
    },
  },
};

//--------------- !! In production add these !! ----------------------

// sameSite: "lax", // Prevents CSRF but allows external-site navigation

// SECURITY: Validate required environment variables
// if (!process.env.NEXTAUTH_SECRET) {
//   throw new Error("NEXTAUTH_SECRET is not defined in environment variables");
// }

// SECURITY: Rate limiter (login with credentials) for brute force protection

// SECURITY: Enhanced email validation with RFC 5322 simplified checks regex

// Consideusing external rate limiting service (e.g., Redis) for production scaling

// Add email verification flow for credential-based signups

// Environment variable validation
// Enhanced email validation (RFC 5322 compliant)
// Removed allowDangerousEmailAccountLinking
// Strict CSRF protection (sameSite: "strict")
// Email verification checks
// OAuth profile validation
// Sanitized error logging (dev vs production)
