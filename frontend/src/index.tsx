import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";

import StoreWrapper from "@stores/index";

import App from "./App";

createRoot(document.getElementById("app") as HTMLElement).render(<StrictMode><BrowserRouter><StoreWrapper><App /></StoreWrapper></BrowserRouter></StrictMode>);
