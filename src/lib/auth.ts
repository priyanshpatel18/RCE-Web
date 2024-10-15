import { db, Provider } from "@/packages/database";
import { AuthOptions, Session } from "next-auth";
import { JWT } from "next-auth/jwt";
import CredentialsProvider from "next-auth/providers/credentials";
import Github from "next-auth/providers/github";
import Google from "next-auth/providers/google";

export interface session extends Session {
  user: {
    id: string;
    email: string;
    name: string;
  };
}

interface token extends JWT {
  uid: string;
  jwtToken: string;
}

interface user {
  id: string;
  name: string;
  email: string;
  token: string;
}

const getUserByEmail = async (email: string, provider: Provider) => {
  try {
    return await db.user.findUnique({ where: { email, provider } });
  } catch (error) {
    console.error("Error fetching user by email:", error);
    return null;
  }
};

export const authOptions: AuthOptions = {
  providers: [
    Github({
      clientId: process.env.GITHUB_CLIENT || "",
      clientSecret: process.env.GITHUB_SECRET || "",
    }),
    Google({
      clientId: process.env.GOOGLE_CLIENT || "",
      clientSecret: process.env.GOOGLE_SECRET || "",
      async profile(profile) {
        const { email, name, picture } = profile;

        // Create or update the user in the database
        const dbUser = await db.user.upsert({
          where: { email },
          update: { name },
          create: {
            email,
            name,
            provider: "GOOGLE",
          },
        });

        return dbUser;
      },
    }),
    CredentialsProvider({
      name: "Credentials",
      credentials: {
        email: { label: "email", type: "text" },
        name: { label: "name", type: "text" },
      },
      async authorize(credentials) {
        try {
          if (!credentials?.email || !credentials.name) {
            throw new Error("Email and name are required");
          }

          const email = credentials.email;
          let user = await getUserByEmail(email, "GUEST");

          if (user) return user;
          return null;
        } catch (error) {
          console.error("Error in credentials authorize:", error);
        }

        return null;
      },
    }),
  ],
  secret: process.env.SECRET_KEY || "",
  callbacks: {
    jwt: async ({ token, user }): Promise<JWT> => {
      const newToken: token = token as token;

      if (user) {
        newToken.uid = user.id;
        newToken.jwtToken = (user as user).token;
      }
      return newToken;
    },
    session: async ({ session, token }) => {
      const newSession: session = session as session;
      if (newSession.user && token.uid) {
        newSession.user.id = token.uid as string;
        newSession.user.email = session.user?.email ?? "";
      }
      return newSession!;
    },
  },
  pages: {
    signIn: "/sign-in",
  },
};
