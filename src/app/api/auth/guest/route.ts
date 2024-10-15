import { db } from "@/packages/database";
import { UserDetails } from "@/packages/types";
import { sign } from "jsonwebtoken";
import { cookies } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import { v4 as uuidv4 } from "uuid";

const JWT_SECRET = process.env.JWT_SECRET || "";
const NODE_ENV = process.env.NODE_ENV === "production";

export async function POST(request: NextRequest) {
  const body = await request.json();
  const guestUUID = "guest-" + uuidv4();
  const userName = body.name || guestUUID;

  try {
    let user = await db.user.findFirst({
      where: {
        name: userName,
      },
    });

    if (user) {
      return NextResponse.json({ message: "Enter unique name" });
    }
    user = await db.user.create({
      data: {
        name: body.name || guestUUID,
        email: userName + "@algowar.com",
        provider: "GUEST",
      },
    });

    if (!user) {
      return NextResponse.json({ message: "User not Created" });
    }

    const token = sign(
      { userId: user.id, name: user.name, isGuest: true },
      JWT_SECRET
    );
    cookies().set("guest", token, {
      httpOnly: true,
      sameSite: NODE_ENV ? "none" : "strict",
      secure: NODE_ENV,
      maxAge: 1000 * 60 * 60 * 24 * 30,
    });

    const userDetails: UserDetails = {
      id: user.id,
      name: user.name,
      token: token,
      isGuest: true,
    };

    return NextResponse.json({ message: "success", user: userDetails });
  } catch (error) {
    console.log(error);
    return NextResponse.json({ message: "Internal Server Error" });
  }
}
