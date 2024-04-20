import { memo, useEffect } from "react";

interface RouteWrapperProps {
  title?: string;
  description?: string;
  background?: boolean;
  header?: boolean;
  sidebar?: boolean;
  topRight?: boolean;
  element: JSX.Element;
  plain?: boolean;
  setTitle: (value: string | undefined) => void;
  setDescription: (value: string | undefined) => void;
  setBackground: (value: boolean) => void;
  setHeader: (value: boolean) => void;
  setSidebar: (value: boolean) => void;
  setTopRight: (value: boolean) => void;
}

const RouteWrapper: React.FC<RouteWrapperProps> = memo(({
  title,
  description,
  background,
  header,
  sidebar,
  topRight,
  element,
  plain,
  setTitle,
  setDescription,
  setBackground,
  setHeader,
  setSidebar,
  setTopRight
}) => {
  useEffect(() => {
    setTitle(title);
    setDescription(description);
    setBackground(background ?? true);

    if (plain) {
      setHeader(false);
      setSidebar(false);
      setTopRight(false);
    } else {
      setHeader(header ?? false);
      setSidebar(sidebar ?? false);
      setTopRight(topRight ?? false);
    }
  }, [
    title,
    description,
    background,
    header,
    sidebar,
    topRight,
    plain,
    setTitle,
    setDescription,
    setBackground,
    setHeader,
    setSidebar,
    setTopRight
  ]);

  return element;
});

export default RouteWrapper;
