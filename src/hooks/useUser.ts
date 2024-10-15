"use client";

import { useEffect, useState } from "react";
const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL;

export interface User {
  id: string;
  name: string;
  token: string;
  isGuest?: boolean;
}

export async function getUser() {
  const response = await fetch(`${BACKEND_URL}/api/auth/refresh`, {
    method: "GET",
    headers: {
      "Content-Type": "application/json",
    },
    credentials: "include",
  });

  if (response.ok) {
    const data = await response.json();
    return data;
  }
  return null;
}

export function useUser() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  async function fetchUser() {
    const userData = await getUser();
    // Ensure This runs once
    setUser(userData?.user || null);
    setLoading(false);
  }

  useEffect(() => {
    fetchUser();
  }, []);

  return { user, loading, setSocketUser: setUser };
}
