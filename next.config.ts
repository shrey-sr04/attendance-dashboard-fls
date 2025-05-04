import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /* config options here */
  images: {
    remotePatterns: [
      {
        protocol: 'https',
        hostname: 'tm-integration-aws.s3.ap-south-1.amazonaws.com',
      },
    ],
  },
  serverRuntimeConfig: {
    timeout: 120000
  }
};

export default nextConfig;
