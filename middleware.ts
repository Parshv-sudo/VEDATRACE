import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// Define the URLs of your protected routes.
// Based on your file structure, these are the pages users
// should only be able to access after logging in.
const protectedRoutes = [
  '/farmers',
  '/consumers',
  '/dashboard',
];

export function middleware(req: NextRequest) {
  // Check if a cookie exists to determine if the user is authenticated.
  // This is a simplified check. A full implementation would verify a JWT.
  const authCookie = req.cookies.get('__Secure-next-auth.session-token');

  // Get the path of the current request.
  const { pathname } = req.nextUrl;

  // Check if the current path is one of the protected routes.
  const isProtectedRoute = protectedRoutes.some(route => pathname.startsWith(route));

  // If the user is not authenticated (no cookie) and is trying to access a protected page,
  // redirect them to the login page.
  if (!authCookie && isProtectedRoute) {
    const url = new URL('/auth/login', req.url);
    url.searchParams.set('message', 'Authentication failed');
    return NextResponse.redirect(url);
  }

  // If the user is authenticated (cookie exists) and they are trying to access the login or signup page,
  // redirect them to the dashboard.
  if (authCookie && (pathname.startsWith('/auth/login') || pathname.startsWith('/auth/signup'))) {
    return NextResponse.redirect(new URL('/dashboard', req.url));
  }
}

// The matcher specifies which paths the middleware should run on.
// This is a general pattern that includes all paths except for static files.
export const config = {
  matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'],
};