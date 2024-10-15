import { db } from "@/packages/database";
import { redisClient } from "@/packages/redis";
import { QueuePayload, RunCodeRequest } from "@/packages/types";
import { NextRequest, NextResponse } from "next/server";

export async function POST(request: NextRequest) {
  const { code, language, userId } = (await request.json()) as RunCodeRequest;

  if (!userId) {
    return NextResponse.json({
      result: "Unauthorized",
      success: false,
    });
  }
  if (!code || !language) {
    return NextResponse.json({
      result: "Code and Language are required",
      success: false,
    });
  }

  try {
    const transaction = await db.$transaction(async () => {
      // Save code to database
      const submission = await db.submission.create({
        data: {
          code,
          language,
          status: "PENDING",
          userId,
        },
      });

      if (!submission) {
        throw new Error("Submission was not saved");
      }

      // Add to queue
      const queue = process.env.REDIS_QUEUE || "redis-queue";
      const queuePayload: QueuePayload = {
        code,
        language,
        userId,
        submissionId: submission.id,
      };

      const queueResult = await redisClient.lpush(
        queue,
        JSON.stringify(queuePayload)
      );

      if (!queueResult) {
        throw new Error("Failed to add submission to the queue");
      }

      return submission;
    });

    if (!transaction) {
      return NextResponse.json({
        result: "Something went wrong",
        success: false,
      });
    }

    return NextResponse.json({
      result: "Submission saved",
      success: true,
    });
  } catch (error) {
    console.error(error);

    return NextResponse.json({
      result: error instanceof Error ? error.message : "Something went wrong",
      success: false,
    });
  }
}
