"use strict";

const components = {
  kali: {
    index: "01 / SOURCE", symbol: "⌁", title: "Kali client",
    description: "Sends actual Modbus/TCP frames in the VM lab. The recorded cases use FC06 writes to registers 23 and 30.",
    input: "Lab test command", output: "Modbus request over TCP", code: "lab_modbus_client.py"
  },
  pfsense: {
    index: "02 / PERIMETER", symbol: "◇", title: "pfSense + Snort",
    description: "The request crosses pfSense WAN em0 before reaching Ubuntu. Snort inline drop rules are available when a generated rule is explicitly deployed.",
    input: "Traffic from Kali 192.168.56.10", output: "Routed traffic toward Ubuntu", code: "deploy_snort_rules_ssh.py"
  },
  gateway: {
    index: "03 / INLINE", symbol: "▣", title: "Ubuntu gateway",
    description: "The gateway holds each supported request while simulation, anomaly scoring and SEM complete. It forwards only an ALLOW decision to mock SCADA.",
    input: "Modbus request from pfSense", output: "Forward once or return a block response", code: "modbus_gateway.py"
  },
  window: {
    index: "04 / AGGREGATE", symbol: "◷", title: "60-second source window",
    description: "Each source IP has its own trailing batch of requests. The window is updated and scored on every arrival, without waiting a full minute.",
    input: "Current and recent requests from one IP", output: "Packet counts, rates and command context", code: "modbus_gateway.py · feature_extractor.py"
  },
  twin: {
    index: "05 / SIMULATE", symbol: "◈", title: "Digital Twin",
    description: "The Physics Engine applies a command to an isolated simulated state and produces process telemetry. A blocked candidate is rolled back before any mock safety action.",
    input: "Current command and prior Twin state", output: "Simulated process state and telemetry", code: "Digital Twin/physics_engine.py"
  },
  ad: {
    index: "06A / SCORE", symbol: "∿", title: "Anomaly detection",
    description: "A calibrated ensemble scores the model's declared features. The current SWaT-process model reads process-state features, not the new 60-second traffic rate.",
    input: "Model feature vector", output: "Score, threshold and anomaly verdict", code: "realtime_anomaly_detector.py"
  },
  sem: {
    index: "06B / EXTRACT", symbol: "⊞", title: "Signature extraction (SEM)",
    description: "In parallel with anomaly scoring, SEM summarizes observed writes in the window. Only the current command can become a command-specific Snort rule after a justified BLOCK.",
    input: "Window statistics and Modbus frames", output: "Candidate signature and command counts", code: "orchestrator.py · rule_generator.py"
  },
  decision: {
    index: "07 / GATE", symbol: "⟡", title: "Decision engine",
    description: "Combines the anomaly result with command attribution and any existing quarantine. The current request is either allowed or withheld before reaching mock SCADA.",
    input: "AD verdict + SEM candidate", output: "ALLOW or BLOCK", code: "decision_engine.py"
  },
  scada: {
    index: "08A / FORWARD", symbol: "◉", title: "Mock SCADA",
    description: "The loopback Modbus server receives an allowed request once and updates its registers. It is a stand-in for a plant, not a physical PLC.",
    input: "Allowed Modbus request", output: "Upstream acknowledgment or read value", code: "mock_scada.py"
  },
  block: {
    index: "08B / WITHHOLD", symbol: "⊘", title: "Block and respond",
    description: "A blocked FC06 write is never forwarded. The client receives Modbus exception 04. A lab-only safety hook can turn mock pump registers OFF.",
    input: "Actionable anomaly or quarantined command", output: "Exception + optional safety response", code: "modbus_gateway.py · mock_scada.py"
  }
};

const cases = {
  normal: {
    scope: "RECORDED VM RUN", path: "KALI → UBUNTU",
    steps: [
      { label: "COMMAND SENT", title: "Normal Modbus write", description: "Kali sends FC06 register 30 = 1 through pfSense to the Ubuntu gateway.", command: "python3 ~/lab_modbus_client.py --host 192.168.58.105 --case normal", detail: "This is the benign valve write used in the recorded VM test.", nodes: ["kali", "pfsense", "gateway"] },
      { label: "SIMULATE", title: "Twin predicts the effect", description: "The inline gateway simulates the write and records the resulting process state before deciding whether to forward it.", command: "modbus_register: 30  ·  modbus_value: 1", detail: "The mock SCADA has not been contacted during this simulation step.", nodes: ["gateway", "twin"] },
      { label: "ANALYZE IN PARALLEL", title: "AD scores; SEM observes", description: "The ensemble evaluates the state. SEM extracts the observed command as a candidate signature; the candidate alone does not cause a block.", command: "AD verdict: normal  ·  SEM candidate: FC06 / 30 / 1", detail: "The current SWaT-process model uses process-state features for its score.", nodes: ["ad", "sem", "decision"] },
      { label: "ALLOW + FORWARD", title: "Mock SCADA acknowledges", description: "The gateway forwards the allowed request once. Kali receives an acknowledgment for register 30 = 1.", command: "Write acknowledged: register 30 = 1", detail: "A later normal write also remained allowed after the register-23 blocks.", nodes: ["decision", "scada"] }
    ]
  },
  buildup: {
    scope: "RECORDED VM RUN", path: "KALI → TWIN → AD",
    steps: [
      { label: "REPEATED INPUT", title: "Forty dosing writes", description: "Kali sends forty FC06 writes of register 23 = 1 through the inline path.", command: "for i in range(1, 41): exchange('192.168.58.105', 5020, 6, 23, 1)", detail: "Register 23 maps to the simulated p203 dosing pump.", nodes: ["kali", "pfsense", "gateway"] },
      { label: "FIRST 32 WRITES", title: "The model still sees normal", description: "Writes 1–32 scored below the process anomaly threshold, so the gateway allowed them and mock SCADA acknowledged them.", command: "writes 1–32 → ALLOW / acknowledged", detail: "This is the measured detection delay; blocking cannot stop a write the detector has classified as normal.", nodes: ["twin", "ad", "decision", "scada"] },
      { label: "THRESHOLD CROSSING", title: "Write 33 trips the ensemble", description: "At write 33, the recorded score was 0.834, above the calibrated threshold of 0.773. The opposite-state counterfactual supported attributing the crossing to this command.", command: "score 0.834 > threshold 0.773  ·  FC06 / 23 / 1", detail: "The exact values are from the recorded VM telemetry, before the rolling-window update.", nodes: ["twin", "ad", "sem", "decision"] },
      { label: "LIMITATION", title: "A delayed detection", description: "The detection happened only after the simulated process had changed over many writes. The new 60-second window records traffic, but this state-only model does not score packet rate.", command: "32 allowed  ·  first detection on write 33", detail: "Earlier burst detection needs a network-aware model trained and calibrated on matching windows.", nodes: ["window", "ad"] }
    ]
  },
  block: {
    scope: "RECORDED VM RUN", path: "GATEWAY → MOCK SAFETY",
    steps: [
      { label: "INLINE BLOCK", title: "Write 33 is withheld", description: "The gateway blocks the triggering write before forwarding it. Kali receives Modbus exception 04 instead of a success acknowledgment.", command: "Write 33 rejected: Modbus exception: 8604", detail: "The blocked command is rolled back in the authoritative Twin.", nodes: ["ad", "decision", "block"] },
      { label: "SEM RULE", title: "A specific rule is generated", description: "SEM identifies the observed FC06 register-23 value-1 command and writes a matching Snort drop rule locally.", command: "drop tcp ... content:'|06 00 17 00 01|' ...", detail: "Automatic pfSense deployment was disabled in this recorded run; local rule generation is not proof of a pfSense drop.", nodes: ["sem", "decision", "block"] },
      { label: "REPEAT ATTEMPTS", title: "Writes 34–40 stay blocked", description: "The same command remains in the running gateway's quarantine. Each repeat receives a Modbus exception, even if its individual model score later falls below threshold.", command: "writes 34–40 → rejected: Modbus exception: 8604", detail: "The quarantine is scoped to this gateway process, not a permanent global policy.", nodes: ["gateway", "decision", "block"] },
      { label: "MOCK RECOVERY", title: "Unsafe pump is OFF", description: "The lab-only safety hook switches mock register 23 OFF. A direct Ubuntu read returned 0; an unrelated register-30 write was still allowed.", command: "Register 23: 0  ·  register 30 = 1 acknowledged", detail: "This is mock-state recovery, not a validated physical PLC safety command.", nodes: ["block", "scada", "decision"] }
    ]
  },
  window: {
    scope: "LATEST LOCAL TEST", path: "ONE IP → ROLLING BATCH",
    steps: [
      { label: "SOURCE ISOLATION", title: "One IP, one rolling batch", description: "The gateway keeps only requests from the same source IP in each 60-second trailing window. Old requests expire and other clients have separate windows.", command: "source 192.0.2.1  ·  window_seconds: 60", detail: "Regression tests cover source isolation and window expiry.", nodes: ["gateway", "window"] },
      { label: "EVERY ARRIVAL", title: "Score before forwarding", description: "The current request joins its source's batch. The gateway immediately simulates and scores that batch before it contacts mock SCADA.", command: "window_packet_count: 1 → 2 → 3", detail: "There is no one-minute wait or queued flush; the window slides on each arrival.", nodes: ["window", "twin", "gateway"] },
      { label: "PARALLEL WORKERS", title: "AD and SEM share context", description: "Two workers run concurrently. AD receives aggregate traffic statistics and current process state; SEM summarizes writes in the batch, while rule attribution remains tied to the current request.", command: "AD: score(batch features)  ∥  SEM: extract(batch context)", detail: "A prior write in the window cannot become a rule for an unrelated current request.", nodes: ["ad", "sem"] },
      { label: "LOCAL VERIFICATION", title: "Counts increase as expected", description: "With the real SWaT-process model and mock SCADA, three local writes produced counts 1, 2 and 3. All three were allowed. The full regression suite passed.", command: "counts: 1, 2, 3  ·  decisions: ALLOW, ALLOW, ALLOW", detail: "The new rolling-window path still needs a repeat Kali-to-Ubuntu VM run. This model does not score traffic rate.", nodes: ["window", "ad", "decision", "scada"] }
    ]
  }
};

const nodeButtons = [...document.querySelectorAll("[data-node]")];
const caseTabs = [...document.querySelectorAll("[data-case]")];
const elements = {
  inspectorIndex: document.getElementById("inspector-index"),
  inspectorSymbol: document.getElementById("inspector-symbol"),
  inspectorHeading: document.getElementById("inspector-heading"),
  inspectorDescription: document.getElementById("inspector-description"),
  inspectorInput: document.getElementById("inspector-input"),
  inspectorOutput: document.getElementById("inspector-output"),
  inspectorCode: document.getElementById("inspector-code"),
  casePanel: document.getElementById("case-panel"),
  caseScope: document.getElementById("case-scope"),
  stepIndicator: document.getElementById("step-indicator"),
  progressFill: document.getElementById("progress-fill"),
  stepLabel: document.getElementById("step-label"),
  stepTitle: document.getElementById("step-title"),
  stepDescription: document.getElementById("step-description"),
  activePath: document.getElementById("active-path"),
  stepCommand: document.getElementById("step-command"),
  stepDetailText: document.getElementById("step-detail-text"),
  stepDots: document.getElementById("step-dots"),
  prevStep: document.getElementById("prev-step"),
  nextStep: document.getElementById("next-step"),
  cardPath: document.querySelector(".card-path")
};

let activeCase = "normal";
let activeStep = 0;

function inspectNode(name) {
  const item = components[name];
  if (!item) return;
  elements.inspectorIndex.textContent = item.index;
  elements.inspectorSymbol.textContent = item.symbol;
  elements.inspectorHeading.textContent = item.title;
  elements.inspectorDescription.textContent = item.description;
  elements.inspectorInput.textContent = item.input;
  elements.inspectorOutput.textContent = item.output;
  elements.inspectorCode.textContent = item.code;
}

function highlightNodes(names) {
  const active = new Set(names);
  nodeButtons.forEach((button) => {
    button.classList.toggle("is-active", active.has(button.dataset.node));
    button.classList.toggle("is-dim", !active.has(button.dataset.node));
  });
}

function renderStep() {
  const test = cases[activeCase];
  const step = test.steps[activeStep];
  elements.caseScope.textContent = test.scope;
  elements.cardPath.textContent = test.path;
  elements.stepIndicator.textContent = `STEP ${String(activeStep + 1).padStart(2, "0")} / ${String(test.steps.length).padStart(2, "0")}`;
  elements.progressFill.style.width = `${((activeStep + 1) / test.steps.length) * 100}%`;
  elements.stepLabel.textContent = step.label;
  elements.stepTitle.textContent = step.title;
  elements.stepDescription.textContent = step.description;
  elements.activePath.replaceChildren(...step.nodes.map((name) => {
    const chip = document.createElement("span");
    chip.textContent = components[name].title;
    return chip;
  }));
  elements.stepCommand.textContent = step.command;
  elements.stepDetailText.textContent = step.detail;
  elements.prevStep.disabled = activeStep === 0;
  elements.nextStep.disabled = activeStep === test.steps.length - 1;
  elements.nextStep.setAttribute("aria-label", activeStep === test.steps.length - 1 ? "End of test case" : "Next step");
  elements.stepDots.replaceChildren(...test.steps.map((item, index) => {
    const dot = document.createElement("button");
    dot.type = "button";
    dot.setAttribute("aria-label", `Go to step ${index + 1}: ${item.title}`);
    if (index === activeStep) dot.setAttribute("aria-current", "step");
    dot.addEventListener("click", () => { activeStep = index; renderStep(); });
    return dot;
  }));
  highlightNodes(step.nodes);
  inspectNode(step.nodes[step.nodes.length - 1]);
}

function selectCase(name) {
  if (!cases[name]) return;
  activeCase = name;
  activeStep = 0;
  caseTabs.forEach((tab) => {
    const selected = tab.dataset.case === name;
    tab.setAttribute("aria-selected", String(selected));
    tab.tabIndex = selected ? 0 : -1;
  });
  elements.casePanel.setAttribute("aria-labelledby", `case-tab-${name}`);
  renderStep();
}

nodeButtons.forEach((button) => {
  button.addEventListener("click", () => {
    highlightNodes([button.dataset.node]);
    inspectNode(button.dataset.node);
  });
});

caseTabs.forEach((tab, index) => {
  tab.addEventListener("click", () => selectCase(tab.dataset.case));
  tab.addEventListener("keydown", (event) => {
    if (event.key !== "ArrowDown" && event.key !== "ArrowUp" && event.key !== "ArrowRight" && event.key !== "ArrowLeft") return;
    event.preventDefault();
    const direction = (event.key === "ArrowDown" || event.key === "ArrowRight") ? 1 : -1;
    const next = caseTabs[(index + direction + caseTabs.length) % caseTabs.length];
    selectCase(next.dataset.case);
    next.focus();
  });
});

elements.prevStep.addEventListener("click", () => {
  if (activeStep > 0) { activeStep -= 1; renderStep(); }
});
elements.nextStep.addEventListener("click", () => {
  if (activeStep < cases[activeCase].steps.length - 1) { activeStep += 1; renderStep(); }
});

selectCase("normal");
