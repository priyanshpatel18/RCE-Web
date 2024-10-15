"use client";

import EditorOutput from "@/components/EditorAndOutput";
import SignInDialog from "@/components/SignInDialog";
import Topbar from "@/components/Topbar";
import useUserSocket from "@/hooks/useUserSocket";
import { CONNECTED, UPDATE_USER } from "@/packages/messages";
import { UserDetails } from "@/packages/types";
import { useEffect, useState } from "react";

export interface Language {
  value: string;
  label: string;
}

export default function Home() {
  const [selectedLanguage, setSelectedLanguage] = useState<Language>({
    value: "PYTHON",
    label: "PYTHON",
  });
  const [isSignedIn, setIsSignedIn] = useState<boolean>(true);
  const [showDialog, setShowDialog] = useState<boolean>(false);
  const [user, setUser] = useState<UserDetails | null>(null);
  const { socket, socketUser, setSocketUser } = useUserSocket();
  const [output, setOutput] = useState<string | null>(null);

  useEffect(() => {
    if (!socketUser) {
      setShowDialog(true);
      setIsSignedIn(false);
      return;
    }
    if (!socket) {
      return;
    }
    if (socketUser) {
      setIsSignedIn(true);
      setShowDialog(false);
      setUser(socketUser);
    }

    const handleMessage = (event: MessageEvent) => {
      const messageData = JSON.parse(event.data);
      if (messageData.type === CONNECTED) {
        console.log(CONNECTED);
      }

      if (messageData.type === UPDATE_USER) {
        setOutput(messageData.payload);
      }
    };

    socket.addEventListener("message", handleMessage);

    return () => {
      socket.removeEventListener("message", handleMessage);
    };
  }, [socket, socketUser, setIsSignedIn]);

  return (
    <div className="flex flex-col h-screen">
      <Topbar
        selectedLanguage={selectedLanguage}
        setSelectedLanguage={setSelectedLanguage}
      />
      <div className="flex-1 overflow-hidden">
        <EditorOutput
          selectedLanguage={selectedLanguage.value}
          isSignedIn={isSignedIn}
          user={user}
          output={output}
          setOutput={setOutput}
        />
      </div>

      <SignInDialog
        isOpen={showDialog}
        setIsOpen={setShowDialog}
        setUser={setSocketUser}
        setIsSignedIn={setIsSignedIn}
      />
    </div>
  );
}
