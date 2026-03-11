import React from "react";
import ReactDOM from "react-dom/client";
import { view } from "@forge/bridge";
import App from "./App";

view.theme.enable();

const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
