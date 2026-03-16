import { redis } from "./rateLimit";

export async function isAccountLocked(email) {
  return await redis.get(`lock:${email}`);
}

export async function resetLoginAttempts(email) {
  await redis.del(`attempts:${email}`);
  await redis.del(`lock:${email}`);
}

export async function getLockTTL(email) {
  return await redis.ttl(`lock:${email}`);
}

export async function registerFailedAttempt(email) {

    const key = `attempts:${email}`;

  const attempts = await redis.incr(`attempts:${email}`);

  // Only set TTL when the key is first created
  if (attempts === 1) {
    await redis.expire(key, 60); // 60 seconds
  }

  if (attempts >= 5) {
    let lockTime = 60; // 1 min
    if (attempts > 10) lockTime = 600;
    if (attempts > 20) lockTime = 3600;
    await redis.set(`lock:${email}`, true, { ex: lockTime });
  }

  console.log("Attempts:", await redis.get(`attempts:${email}`));

  return attempts;
}