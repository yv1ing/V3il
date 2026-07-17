import React from "react";
import ReactDOM, { hydrateRoot } from "react-dom/client";
import "./app/styles/landing-static.css";
import v3ilLogo from "./assets/v3il-logo.png";
import { LandingContent } from "./features/landing/LandingContent";
import { landingPrimaryAction } from "./features/landing/landingConfig";

const rootElement = document.getElementById("root") as HTMLElement;
const landing = (
  <React.StrictMode>
    <LandingContent logoSrc={v3ilLogo} primaryAction={landingPrimaryAction} />
  </React.StrictMode>
);

if (rootElement.hasChildNodes()) {
  hydrateRoot(rootElement, landing);
} else {
  ReactDOM.createRoot(rootElement).render(landing);
}
