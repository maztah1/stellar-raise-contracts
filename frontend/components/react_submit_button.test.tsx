/**
 * @title React Submit Button Security and Reliability Tests
 * @notice Covers label safety, state transitions, and interaction blocking rules.
 */
import {
  isSubmitButtonBusy,
  isSubmitButtonInteractionBlocked,
  isValidSubmitButtonStateTransition,
  normalizeSubmitButtonLabel,
  resolveSafeSubmitButtonState,
  resolveSubmitButtonLabel,
  type SubmitButtonLabels,
  type SubmitButtonState,
} from "./react_submit_button";

describe("normalizeSubmitButtonLabel", () => {
  it("returns fallback for non-string values", () => {
    expect(normalizeSubmitButtonLabel(undefined, "Submit")).toBe("Submit");
    expect(normalizeSubmitButtonLabel(404, "Submit")).toBe("Submit");
    expect(normalizeSubmitButtonLabel({}, "Submit")).toBe("Submit");
  });

  it("returns fallback for empty or whitespace labels", () => {
    expect(normalizeSubmitButtonLabel("", "Submit")).toBe("Submit");
    expect(normalizeSubmitButtonLabel("   \n\t", "Submit")).toBe("Submit");
  });

  it("removes control characters and normalizes whitespace", () => {
    const dirtyLabel = "Pay\u0000\u0008\n   Now";
    expect(normalizeSubmitButtonLabel(dirtyLabel, "Submit")).toBe("Pay Now");
  });

  it("truncates labels above the maximum bound", () => {
    const longLabel = "A".repeat(200);
    const normalized = normalizeSubmitButtonLabel(longLabel, "Submit");

    expect(normalized).toHaveLength(80);
    expect(normalized.endsWith("...")).toBe(true);
  });
});

describe("resolveSubmitButtonLabel", () => {
  it("returns defaults for every known state", () => {
    const states: SubmitButtonState[] = ["idle", "submitting", "success", "error", "disabled"];
    const labels = states.map((state) => resolveSubmitButtonLabel(state));

    expect(labels).toEqual(["Submit", "Submitting...", "Submitted", "Try Again", "Submit Disabled"]);
  });

  it("uses sanitized custom labels", () => {
    const customLabels: SubmitButtonLabels = {
      success: "  Campaign submitted successfully  ",
    };

    expect(resolveSubmitButtonLabel("success", customLabels)).toBe("Campaign submitted successfully");
  });

  it("keeps hostile markup-like text as inert string content", () => {
    const hostile = "<img src=x onerror=alert(1) />";
    const labels: SubmitButtonLabels = { error: hostile };

    // Security assumption: React escapes text nodes, so this remains plain text content.
    expect(resolveSubmitButtonLabel("error", labels)).toBe(hostile);
  });
});

describe("isValidSubmitButtonStateTransition", () => {
  it("allows expected forward transitions", () => {
    expect(isValidSubmitButtonStateTransition("idle", "submitting")).toBe(true);
    expect(isValidSubmitButtonStateTransition("submitting", "success")).toBe(true);
    expect(isValidSubmitButtonStateTransition("submitting", "error")).toBe(true);
    expect(isValidSubmitButtonStateTransition("error", "submitting")).toBe(true);
    expect(isValidSubmitButtonStateTransition("disabled", "idle")).toBe(true);
  });

  it("allows same-state transitions (idempotent updates)", () => {
    expect(isValidSubmitButtonStateTransition("idle", "idle")).toBe(true);
    expect(isValidSubmitButtonStateTransition("success", "success")).toBe(true);
  });

  it("blocks invalid transitions", () => {
    expect(isValidSubmitButtonStateTransition("idle", "success")).toBe(false);
    expect(isValidSubmitButtonStateTransition("success", "error")).toBe(false);
    expect(isValidSubmitButtonStateTransition("disabled", "submitting")).toBe(false);
  });
});

describe("resolveSafeSubmitButtonState", () => {
  it("returns requested state when transition is valid", () => {
    expect(resolveSafeSubmitButtonState("submitting", "idle", true)).toBe("submitting");
  });

  it("falls back to previous state for invalid strict transitions", () => {
    expect(resolveSafeSubmitButtonState("success", "idle", true)).toBe("idle");
  });

  it("accepts requested state when strict mode is disabled", () => {
    expect(resolveSafeSubmitButtonState("success", "idle", false)).toBe("success");
  });

  it("accepts requested state when previous state is unavailable", () => {
    expect(resolveSafeSubmitButtonState("error", undefined, true)).toBe("error");
  });
});

describe("interaction and busy guards", () => {
  it("blocks interaction for disabled and submitting states", () => {
    expect(isSubmitButtonInteractionBlocked("submitting")).toBe(true);
    expect(isSubmitButtonInteractionBlocked("disabled")).toBe(true);
  });

  it("blocks interaction when explicit or local flags are set", () => {
    expect(isSubmitButtonInteractionBlocked("idle", true, false)).toBe(true);
    expect(isSubmitButtonInteractionBlocked("idle", false, true)).toBe(true);
  });

  it("allows interaction for active states when flags are clear", () => {
    expect(isSubmitButtonInteractionBlocked("idle", false, false)).toBe(false);
    expect(isSubmitButtonInteractionBlocked("error", false, false)).toBe(false);
    expect(isSubmitButtonInteractionBlocked("success", false, false)).toBe(false);
  });

  it("sets busy only for submitting or local in-flight execution", () => {
    expect(isSubmitButtonBusy("submitting", false)).toBe(true);
    expect(isSubmitButtonBusy("idle", true)).toBe(true);
    expect(isSubmitButtonBusy("idle", false)).toBe(false);
  });
});
