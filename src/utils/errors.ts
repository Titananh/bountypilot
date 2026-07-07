export class BountyPilotError extends Error {
  constructor(
    message: string,
    readonly code: string,
  ) {
    super(message);
    this.name = "BountyPilotError";
  }
}
