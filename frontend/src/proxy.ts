import { NextRequest, NextResponse } from "next/server";
import { jwtVerify } from "jose";

const secret = new TextEncoder().encode(process.env.JWT_ACCESS_SECRET);
const apiBaseUrl =
  process.env.NEXT_PUBLIC_API_URL ?? process.env.API_URL ?? "http://localhost:5000";

export async function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;

  const accessToken = request.cookies.get("access_token")?.value;
  const refreshToken = request.cookies.get("refresh_token")?.value;

  console.log("PATH:", pathname);
  console.log("ACCESS:", accessToken ? "EXISTS" : "MISSING");
  console.log("REFRESH:", refreshToken ? "EXISTS" : "MISSING");

  // Allow login route without auth checks
  if (pathname === "/login") {
    return NextResponse.next();
  }

  // No access token
  if (!accessToken) {
    if (!refreshToken) {
      console.log("❌ No token at all → /login");
      return NextResponse.redirect(new URL("/login", request.url));
    }

    // Has refresh token -> try refresh
    return await tryRefresh(request, refreshToken);
  }

  try {
    const { payload } = await jwtVerify(accessToken, secret);
    const role = payload.role as string;

    console.log("✅ TOKEN VALID:", role);

    // 🔥 redirect từ "/"
    if (pathname === "/") {
      if (role === "ADMIN") {
        return NextResponse.redirect(new URL("/admin/dashboard", request.url));
      }
      if (role === "DOCTOR") {
        return NextResponse.redirect(new URL("/doctor/dashboard", request.url));
      }
      return NextResponse.redirect(new URL("/403", request.url));
    }

    // 🔥 protect admin
    if (pathname.startsWith("/admin") && role !== "ADMIN") {
      return NextResponse.redirect(new URL("/403", request.url));
    }

    // 🔥 protect doctor
    if (pathname.startsWith("/doctor") && role !== "DOCTOR") {
      return NextResponse.redirect(new URL("/403", request.url));
    }

    return NextResponse.next();

  } catch (err: any) {
    console.log("❌ ACCESS TOKEN EXPIRED");

    // Access token expired -> use refresh token
    if (refreshToken) {
      return await tryRefresh(request, refreshToken);
    }

    return NextResponse.redirect(new URL("/login", request.url));
  }
}

async function tryRefresh(request: NextRequest, refreshToken: string) {
  try {
    console.log("🔄 Trying refresh token...");

    const res = await fetch(`${apiBaseUrl}/auth/refresh`, {
      method: "POST",
      headers: {
        Cookie: `refresh_token=${refreshToken}`,
      },
    });

    if (!res.ok) {
      console.log("❌ Refresh failed");
      return NextResponse.redirect(new URL("/login", request.url));
    }

    const data = await res.json().catch(() => null);
    const newAccessToken = data?.accessToken ?? data?.access_token;

    console.log("✅ Refresh success");

    if (typeof newAccessToken !== "string" || !newAccessToken) {
      console.log("❌ Refresh response missing access token");
      return NextResponse.redirect(new URL("/login", request.url));
    }

    // Set new cookie
    const response = NextResponse.next();

    response.cookies.set("access_token", newAccessToken, {
      httpOnly: true,
      path: "/",
    });

    return response;

  } catch (error) {
    console.log("❌ Refresh error");
    return NextResponse.redirect(new URL("/login", request.url));
  }
}

export const config = {
  matcher: [
    "/",
    "/admin/:path*",
    "/doctor/:path*",
  ],
};