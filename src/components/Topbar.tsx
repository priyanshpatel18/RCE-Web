"use client";

import { Language } from "@/app/page";
import { motion } from "framer-motion";
import { Dispatch, SetStateAction, useEffect, useRef, useState } from "react";

interface TopbarProps {
  selectedLanguage: Language;
  setSelectedLanguage: Dispatch<SetStateAction<Language>>;
}

const languages: Language[] = [
  { value: "PYTHON", label: "PYTHON" },
  { value: "JAVASCRIPT", label: "JAVASCRIPT" },
  { value: "TYPESCRIPT", label: "TYPESCRIPT" },
  { value: "C", label: "C" },
  { value: "CPP", label: "C++" },
  { value: "JAVA", label: "JAVA" },
];

export default function Topbar({
  selectedLanguage,
  setSelectedLanguage,
}: TopbarProps) {
  const [isOpen, setIsOpen] = useState<boolean>(false);
  const dropdownRef = useRef<HTMLDivElement | null>(null);

  const handleClickOutside = (event: Event) => {
    if (
      dropdownRef.current &&
      !dropdownRef.current.contains(event.target as Node)
    ) {
      setIsOpen(false);
    }
  };

  useEffect(() => {
    document.addEventListener("mousedown", handleClickOutside);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, []);

  const handleLanguageSelect = (language: Language) => {
    setSelectedLanguage(language);
    setIsOpen(false);
  };

  return (
    <div className="z-10 bg-gray-900 text-white p-4 flex justify-end items-center">
      <div className="relative" ref={dropdownRef}>
        <button
          onClick={() => setIsOpen(!isOpen)}
          className="bg-gray-800 w-48 px-4 py-2 rounded-md"
        >
          {selectedLanguage ? selectedLanguage.label : "Languages"}
        </button>

        {isOpen && (
          <motion.ul
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="absolute right-0 mt-2 w-48 bg-white text-black rounded-md shadow-lg overflow-hidden"
          >
            {languages.map(({ value, label }) => (
              <li
                key={value}
                className="px-4 py-2 hover:bg-blue-100 cursor-pointer"
                onClick={() => handleLanguageSelect({ value, label })}
              >
                {label}
              </li>
            ))}
          </motion.ul>
        )}
      </div>
    </div>
  );
}
