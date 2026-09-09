/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  experimental: {
    serverComponentsExternalPackages: ["mongoose", "ioredis", "bullmq"],
  },
};

export default nextConfig;
