import { Language, Submission, User } from "@prisma/client";

export interface QueuePayload {
  language: Language;
  code: string;
  userId: User["id"];
  submissionId: Submission["id"];
}

export interface RunCodeRequest {
  language: Language;
  code: string;
  userId: User["id"];
}

export interface UserDetails {
  id: User["id"];
  name: User["name"];
  token?: string;
  isGuest?: boolean;
}