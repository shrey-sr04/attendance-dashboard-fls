import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { verify } from 'jsonwebtoken';
import { verifyToken } from './lib/jwt';
import { UserRole } from './types/apollo-admin';

const allowedOrigins = [
    // Development
    'http://localhost:3000',
    'http://localhost:8081',
    'http://localhost:19006',
    'exp://*',

    // Production domains
    'https://tools.onxtasks.com',
    'https://*.amazonaws.com',
    'file://*',
    'content://*',
    null, // Allow requests with no origin
];

// Define types for rate limiting
type TimeStamp = number;
type RequestLog = TimeStamp[];
type RateLimitStore = Map<string, RequestLog>;

// Simple in-memory store for rate limiting
const rateLimit: RateLimitStore = new Map();

function getRateLimitResult(ip: string, limit: number = 100, windowMs: number = 60000): boolean {
    const now = Date.now();
    const windowStart = now - windowMs;

    const identifier = `${ip}`;
    const userRequests = rateLimit.get(identifier) || [];

    // Clean old requests
    const recentRequests = userRequests.filter((timestamp: TimeStamp) => timestamp > windowStart);

    if (recentRequests.length >= limit) {
        return false;
    }

    recentRequests.push(now);
    rateLimit.set(identifier, recentRequests);

    // Cleanup old entries periodically
    if (Math.random() < 0.001) { // 0.1% chance to clean up on each request
        for (const [key, timestamps] of rateLimit.entries()) {
            rateLimit.set(
                key,
                timestamps.filter((ts: TimeStamp) => ts > windowStart)
            );
            if (rateLimit.get(key)?.length === 0) {
                rateLimit.delete(key);
            }
        }
    }

    return true;
}

function getClientIp(request: NextRequest): string {
    const forwardedFor = request.headers.get('x-forwarded-for');
    if (forwardedFor) {
        return forwardedFor.split(',')[0].trim();
    }

    const realIp = request.headers.get('x-real-ip');
    if (realIp) {
        return realIp;
    }

    return '0.0.0.0';
}

async function verifyAuthToken(request: NextRequest): Promise<boolean> {
    const token = request.cookies.get('token')?.value;

    if (!token) {
        return false;
    }

    try {
        verify(token, process.env.JWT_SECRET!);
        return true;
    } catch {
        return false;
    }
}

// Verify Apollo Admin token
async function verifyApolloAdminToken(request: NextRequest): Promise<{ isValid: boolean; userData?: any }> {
    const adminToken = request.cookies.get('apollo_admin_token')?.value;
    const guestToken = request.cookies.get('apollo_guest_token')?.value;

    console.log("Admin Token:", adminToken ? adminToken.substring(0, 10) + "..." : "missing");
    console.log("Guest Token:", guestToken ? guestToken.substring(0, 10) + "..." : "missing");


    if (!adminToken && !guestToken) {
        console.log("No tokens found");
        return { isValid: false };
    }

    try {
        // Try admin token first
        if (adminToken) {
            try {
                const decoded = await verifyToken(adminToken);
                console.log("Admin token decoded:", decoded);
                if (decoded.role === UserRole.ADMIN || decoded.role === UserRole.SUPER_ADMIN) {
                    return {
                        isValid: true,
                        userData: {
                            userId: decoded.userId,
                            role: decoded.role
                        }
                    };
                }
            } catch (error) {
                console.error("Admin token decode error:", error);
            }

        }

        // Try guest token if admin token is not valid
        if (guestToken) {
            const decoded = await verifyToken(guestToken);
            if (decoded.role === UserRole.GUEST) {
                return {
                    isValid: true,
                    userData: {
                        userId: decoded.userId,
                        role: UserRole.GUEST
                    }
                };
            }
        }

        return { isValid: false };
    } catch {
        return { isValid: false };
    }
}

function isProtectedRoute(pathname: string): boolean {
    // Add exception for the public admin API endpoint
    if (pathname === '/api/admin/getDeatils') {
        return false;
    }

    return (
        pathname.startsWith('/attendance') ||
        pathname.startsWith('/auth/shifts') ||
        pathname.startsWith('/shifts')
    );
}

function isApolloAdminRoute(pathname: string): boolean {
    if (pathname === '/api/admin/approve') {
        return false;
    }

    return (
        pathname.startsWith('/api/apollo/qc') ||
        pathname.startsWith('/api/apolloadmin')
    );
}

// Function to check if route is an Apollo API route that needs API key
function isApolloApiRoute(pathname: string): boolean {
    // Don't require API key for auth routes
    if (pathname.startsWith('/api/apollo/auth/') ||
        pathname.startsWith('/api/auth/')) {
        return false;
    }

    return pathname.startsWith('/api/apollo');
}

function isPublicApiRoute(pathname: string): boolean {
    return pathname === '/api/admin/getDeatils';
}

export async function middleware(request: NextRequest) {
    const origin = request.headers.get('origin');
    const clientIp = getClientIp(request);
    const pathname = request.nextUrl.pathname;

    // Special handling for Apollo admin routes
    if (isApolloAdminRoute(pathname)) {
        const { isValid, userData } = await verifyApolloAdminToken(request);

        if (!isValid) {
            return new NextResponse(
                JSON.stringify({ error: 'Unauthorized. Admin access required.' }),
                {
                    status: 401,
                    headers: {
                        'Content-Type': 'application/json',
                    },
                }
            );
        }

        // If valid, add user data to headers
        const requestHeaders = new Headers(request.headers);
        requestHeaders.set('x-user-id', userData.userId.toString());
        requestHeaders.set('x-user-role', userData.role);

        // Continue with the request
        const response = NextResponse.next({
            request: {
                headers: requestHeaders,
            },
        });

        // Set CORS headers
        response.headers.set('Access-Control-Allow-Origin', origin || '*');
        response.headers.set('Access-Control-Allow-Credentials', 'true');
        response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
        response.headers.set('Access-Control-Allow-Headers', [
            'Content-Type',
            'Authorization',
            'x-user-id',
            'x-user-role',
            'x-api-key',
            'X-Requested-With',
            'Accept',
            'Origin',
            'Access-Control-Allow-Headers'
        ].join(', '));

        return response;
    }

    // Special handling for Apollo API routes (allow QC dashboard API)
    if (isApolloApiRoute(pathname)) {
        // Verify Apollo API key
        const apiKey = request.headers.get('x-api-key');

        if (!apiKey || apiKey !== process.env.APOLLO_API_KEY) {
            return new NextResponse(
                JSON.stringify({ error: 'Invalid API Key' }),
                {
                    status: 401,
                    headers: {
                        'Content-Type': 'application/json',
                    },
                }
            );
        }

        return handleCorsResponse(request, '*', true, clientIp);
    }

    // Special handling for public API endpoints
    if (isPublicApiRoute(pathname)) {
        // Verify API key for public endpoints
        const url = new URL(request.url);
        const apiKey = url.searchParams.get('api_key');

        if (!apiKey || apiKey !== process.env.ADMIN_API_KEY) {
            return new NextResponse(
                JSON.stringify({ error: 'Invalid API Key' }),
                {
                    status: 401,
                    headers: {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*',
                        'Access-Control-Allow-Methods': 'GET, OPTIONS',
                    },
                }
            );
        }

        // If API key is valid, allow the request to proceed
        return handleCorsResponse(request, '*', true, clientIp);
    }

    // Rest of your existing middleware code...
    if (!origin) {
        return handleCorsResponse(request, '*', true, clientIp);
    }

    const isDevelopment = process.env.NODE_ENV === 'development';

    if (isDevelopment) {
        return handleCorsResponse(request, origin, true, clientIp);
    }

    const isAllowedOrigin = allowedOrigins.includes(origin) ||
        allowedOrigins.some(allowed =>
            allowed && allowed.includes('*') &&
            new RegExp(allowed.replace('*', '.*')).test(origin)
        );

    if (isProtectedRoute(pathname)) {
        const isAuthenticated = await verifyAuthToken(request);
        if (!isAuthenticated) {
            return new NextResponse(
                JSON.stringify({ error: 'Authentication required' }),
                {
                    status: 401,
                    headers: {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': isAllowedOrigin ? origin : '',
                        'Access-Control-Allow-Credentials': 'true',
                    },
                }
            );
        }
    }

    return handleCorsResponse(request, isAllowedOrigin ? origin : '', isAllowedOrigin, clientIp);
}


function handleCorsResponse(
    request: NextRequest,
    origin: string,
    isAllowed: boolean,
    clientIp: string
): NextResponse {
    // Check rate limit for API routes
    if (request.nextUrl.pathname.startsWith('/api/')) {
        const limit = request.nextUrl.pathname === '/api/process-bulk' ? 10 : 100;
        const isWithinLimit = getRateLimitResult(clientIp, limit);

        if (!isWithinLimit) {
            return new NextResponse('Too Many Requests', {
                status: 429,
                headers: {
                    'Retry-After': '60',
                    'Access-Control-Allow-Origin': origin === '*' ? '*' : origin,
                }
            });
        }
    }

    // Handle preflight requests
    if (request.method === 'OPTIONS') {
        return new NextResponse(null, {
            status: 204,
            headers: {
                'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, OPTIONS',
                'Access-Control-Allow-Headers': [
                    'Content-Type',
                    'Authorization',
                    'X-Requested-With',
                    'x-user-id',
                    'x-user-role',
                    'x-api-key',
                    'Accept',
                    'Origin',
                    'Access-Control-Allow-Headers'
                ].join(', '),
                'Access-Control-Max-Age': '86400',
                'Access-Control-Allow-Origin': origin === '*' ? '*' : origin,
                'Access-Control-Allow-Credentials': 'true',
            },
        });
    }

    const response = NextResponse.next();

    // Set CORS headers
    response.headers.set('Access-Control-Allow-Origin', origin === '*' ? '*' : origin);
    response.headers.set('Access-Control-Allow-Credentials', 'true');
    response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
    response.headers.set('Access-Control-Allow-Headers', [
        'Content-Type',
        'Authorization',
        'X-Requested-With',
        'x-user-id',
        'x-user-role',
        'x-api-key',
        'Accept',
        'Origin',
        'Access-Control-Allow-Headers'
    ].join(', '));

    // Security headers
    response.headers.set('X-Content-Type-Options', 'nosniff');
    response.headers.set('X-Frame-Options', 'DENY');
    response.headers.set('X-XSS-Protection', '1; mode=block');
    response.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');

    // Content Security Policy for image processing
    if (request.nextUrl.pathname.startsWith('/api/process-bulk')) {
        response.headers.set('Content-Security-Policy', `
            default-src 'self';
            img-src 'self' data: https://*.amazonaws.com;
            connect-src 'self' https://*.amazonaws.com;
        `.replace(/\s+/g, ' ').trim());
    }

    return response;
}

export const config = {
    matcher: [
        '/api/:path*',
        '/shifts/:path*',
        '/attendance/:path*',
        '/qc/:path*',
        '/((?!_next/static|_next/image|favicon.ico).*)',
    ],
};