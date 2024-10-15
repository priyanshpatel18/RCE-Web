"use client";

import { UserDetails } from "@/packages/types";
import { Editor } from "@monaco-editor/react";
import { Dispatch, SetStateAction, useRef, useState } from "react";
import { toast } from "sonner";

interface EditorOutputProps {
  selectedLanguage: string;
  user: UserDetails | null;
  isSignedIn: boolean;
  output: string | null;
  setOutput: Dispatch<SetStateAction<string | null>>;
}

const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL;

export default function EditorOutput({
  selectedLanguage,
  user,
  output,
  setOutput,
}: EditorOutputProps) {
  const editorRef = useRef<null | any>(null);
  const [loading, setLoading] = useState(false);

  function handleEditorDidMount(editor: any) {
    editorRef.current = editor;
  }

  function cleanOutput(output: string): string {
    return output
      .replace(/[^\x20-\x7E\n\r]/g, "")
      .replace(/\\n/g, "\n")
      .replace(/\\t/g, "\t")
      .replace(/\\r/g, "\r")
      .trim();
  }

  async function handleRunCode() {
    setOutput(null);

    const json = {
      userId: user?.id,
      code: editorRef.current.getValue(),
      language: selectedLanguage.toUpperCase(),
    };

    setLoading(true);

    try {
      const response = await fetch(`${BACKEND_URL}/api/run`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(json),
      });

      if (!response.ok) {
        throw new Error("Network response was not ok");
      }

      const data = await response.json();

      if (data.error) {
        throw new Error(data.error);
      }

      if (data.success) {
        toast.info("Code Submitted!");
      } else {
        toast.error("Code execution failed.");
      }
      setOutput(data.result);
    } catch (error) {
      console.log(error);

      if (error instanceof Error) {
        toast.error(`Error: ${error.message}`);
        setOutput(`Error: ${error.message}`);
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex h-full bg-gradient-to-r from-gray-900 to-gray-950 overflow-hidden">
      {/* Code Editor */}
      <div className="w-1/2 flex flex-col border-r border-gray-700">
        <Editor
          height="100%"
          defaultValue="print('Hello, World!')"
          language={selectedLanguage.toLowerCase()}
          theme="vs-dark"
          onMount={handleEditorDidMount}
          options={{
            minimap: { enabled: false },
            fontSize: 18,
            wordWrap: "on",
            autoDetectHighContrast: false,
          }}
        />
      </div>

      {/* Output Section */}
      <div className="flex flex-col w-1/2 p-6 bg-gray-900 bg-opacity-80 border-l border-gray-800 rounded-md backdrop-blur-md">
        {/* Run Button */}
        <button
          className={`px-6 h-12 rounded-lg text-white transition-all duration-300 shadow-md ${
            loading ? "bg-gray-600" : "bg-indigo-700 hover:bg-indigo-500"
          } disabled:bg-gray-600`}
          onClick={handleRunCode}
          // disabled={loading || !isSignedIn}
        >
          {loading ? (
            <span className="animate-pulse">Running...</span>
          ) : (
            "Run Code"
          )}
        </button>

        {/* Output Heading */}
        <h3 className="text-xl font-semibold mt-4 mb-2 text-gray-300 tracking-wide">
          Output:
        </h3>

        {/* Output Box */}
        <pre className="flex-grow overflow-hidden p-4 bg-gray-800 bg-opacity-80 border border-gray-700 rounded-lg text-white shadow-inner">
          {(typeof output === "string" && cleanOutput(output)) ||
            "No output yet"}
        </pre>
      </div>
    </div>
  );
}
