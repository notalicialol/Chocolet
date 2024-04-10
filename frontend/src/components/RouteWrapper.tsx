import React, { memo, useEffect } from "react";

interface Route {
  title?: string;
  description?: string;
  plain?: boolean;
  topRight?: React.ReactNode;
  header?: boolean;
  sidebar?: boolean;
  element: React.ReactNode;
}

interface RouteWrapperProps {
  route: Route;
  setTitle: (title: string | undefined) => void;
  setDescription: (description: string | undefined) => void;
  setBackground: (background: boolean | undefined) => void;
  setHeader: (header: boolean) => void;
  setSidebar: (sidebar: boolean) => void;
  setTopRight: (topRight: React.ReactNode | undefined) => void;
  title: string | undefined;
  description: string | undefined;
  background: boolean | undefined;
  header: boolean;
  sidebar: boolean;
  topRight: React.ReactNode | undefined;
}

const RouteWrapper: React.FC<RouteWrapperProps> = memo(
  ({
    route,
    setTitle,
    setDescription,
    setBackground,
    setHeader,
    setSidebar,
    setTopRight,
    title,
    description,
    background,
    header,
    sidebar,
    topRight,
  }) => {
    useEffect(() => {
      if (title !== route.title) setTitle(route?.title);
      if (description !== route.description) setDescription(route?.description);

      setBackground(background ?? true);

      if (route.plain) {
        setHeader(false);
        setSidebar(false);
        setTopRight(false);
      } else {
        if (topRight !== route.topRight) setTopRight(route?.topRight);
        
        if (header !== route.header) {
          setHeader(route?.header || false);
          if (route.header) {
            if (sidebar) setSidebar(false);
            if (topRight) setTopRight(false);
          }
        }

        if (route.sidebar && !sidebar) {
          setHeader(false);
          setSidebar(true);
        }
      }
    }, [route, title, description, background, header, sidebar, topRight, setTitle, setDescription, setBackground, setHeader, setSidebar, setTopRight]);

    return <>{route.element}</>;
  }
);

export default RouteWrapper;
