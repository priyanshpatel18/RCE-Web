"use client";

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogOverlay,
  DialogTitle,
} from "@/components/ui/dialog";
import { User } from "@/hooks/useUser";
import { Provider } from "@/packages/database";
import { signIn } from "next-auth/react";
import Image from "next/image";
import { Dispatch, FormEvent, SetStateAction, useRef, useState } from "react";
import githubImage from "../../public/assets/github.png";
import googleImage from "../../public/assets/google.png";
import { Button } from "./ui/button";
import { Separator } from "./ui/separator";

const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL;

export interface SignInDialogProps {
  isOpen: boolean;
  setIsOpen: Dispatch<SetStateAction<boolean>>;
  setUser: Dispatch<SetStateAction<User | null>>;
  setIsSignedIn: Dispatch<SetStateAction<boolean>>;
}

export default function SignInDialog({
  isOpen,
  setIsOpen,
  setUser,
  setIsSignedIn,
}: SignInDialogProps) {
  const guestName = useRef<HTMLInputElement>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [googleLoading, setGoogleLoading] = useState<boolean>(false);
  const [githubLoading, setGithubLoading] = useState<boolean>(false);
  const [guestLoading, setGuestLoading] = useState<boolean>(false);

  async function handleAuth(provider: Provider) {
    setLoading(true);
    if (provider === "GITHUB") {
      setGithubLoading(true);
      await signIn("github");
    } else if (provider === "GOOGLE") {
      setGoogleLoading(true);
      await signIn("google");
    }
    setLoading(false);
    setGithubLoading(false);
    setGoogleLoading(false);
    setIsOpen(false);
  }

  async function loginAsGuest(e: FormEvent) {
    e.preventDefault();
    setLoading(true);
    setGuestLoading(true);

    try {
      const response = await fetch(`${BACKEND_URL}/api/auth/guest`, {
        method: "post",
        headers: {
          "Content-Type": "application/json",
        },
        credentials: "include",
        body: JSON.stringify({ name: guestName.current?.value }),
      });

      const { user } = await response.json();
      if (user) {
        setUser(user);
        setIsSignedIn(true);
      } else {
        setUser(null);
        setIsSignedIn(false);
      }
    } catch (error) {
      console.error("Failed to login as guest:", error);
    } finally {
      setGuestLoading(false);
      setLoading(false);
      setIsOpen(false);
    }
  }

  return (
    <Dialog open={isOpen}>
      <DialogOverlay className="bg-black" />
      <DialogContent className="bg-transparent border-none text-white">
        <DialogHeader>
          <DialogTitle className="text-center text-3xl">
            Sign in to your account
          </DialogTitle>
        </DialogHeader>
        <DialogDescription>
          <div className="flex flex-col gap-6 w-full">
            <div className="flex flex-col sm:flex-row gap-4 mt-4">
              <Button
                variant="secondary"
                className="w-full"
                onClick={() => handleAuth("GOOGLE")}
                disabled={loading}
              >
                {googleLoading ? (
                  <div className="loader-dark" />
                ) : (
                  <div className="flex items-center gap-4">
                    <Image
                      src={googleImage}
                      alt="Google Login"
                      width={25}
                      height={25}
                      className="cursor-pointer"
                    />
                    <span>Google</span>
                  </div>
                )}
              </Button>
              <Button
                variant="secondary"
                className="w-full"
                onClick={() => handleAuth("GITHUB")}
                disabled={loading}
              >
                {githubLoading ? (
                  <div className="loader-dark" />
                ) : (
                  <div className="flex items-center gap-4">
                    <Image
                      src={githubImage}
                      alt="Github Login"
                      width={25}
                      height={25}
                      className="cursor-pointer"
                    />
                    <span>Github</span>
                  </div>
                )}
              </Button>
            </div>
            <div className="relative">
              <Separator />
              <span className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 px-4 uppercase text-white text-xs lg:text-sm bg-black">
                or continue with
              </span>
            </div>
            <form className="flex flex-col gap-6" onSubmit={loginAsGuest}>
              <label htmlFor="name" className="w-full">
                <input
                  id="name"
                  className="w-full px-4 py-2 bg-foreground border-[1px] border-border rounded-md outline-none focus:border-white focus:ring-[0.5px] focus:ring-white text-white text-lg"
                  placeholder="Enter name"
                  ref={guestName}
                  required
                  aria-label="Guest name"
                />
              </label>
              <Button
                variant="secondary"
                type="submit"
                disabled={loading}
                className={`relative ${guestLoading ? "opacity-50" : ""}`}
              >
                {guestLoading ? (
                  <div className="loader-light" />
                ) : (
                  "Continue as Guest"
                )}
              </Button>
            </form>
          </div>
        </DialogDescription>
      </DialogContent>
    </Dialog>
  );
}
