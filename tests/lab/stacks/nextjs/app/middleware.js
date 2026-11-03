// The authorization check lives in middleware, which is the precondition of CVE-2025-29927:
// /protected answers 401 unless the session cookie is present.
import { NextResponse } from 'next/server';

export function middleware(req) {
  if (req.cookies.get('session')?.value !== 'letmein') {
    return new NextResponse('denied', { status: 401 });
  }
  return NextResponse.next();
}

export const config = { matcher: ['/protected/:path*', '/protected'] };
