import { ReactNode } from "react";

import { LoadingProvider } from "./LoadingStore";

export default function StoreWrapper({ children }: { children: ReactNode }) {
  return (
    <LoadingProvider>
      {children}
    </LoadingProvider>
  );
}
