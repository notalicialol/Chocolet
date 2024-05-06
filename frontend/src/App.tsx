import { useState, useEffect } from "react";
import { Routes, Route } from "react-router-dom";
import { Helmet } from "react-helmet";

import "./all.scss";
import routes from "@routes/index";
import pages from "@pages/index";
import { useLoading } from "@stores/LoadingStore";
import { Background, RouteWrapper } from "@components/index";

type RouteType = {
  path: string;
  element: JSX.Element;
  title?: string;
  description?: string;
  background?: boolean;
  header?: boolean;
  sidebar?: boolean;
  topRight?: boolean;
  plain?: boolean;
};

const App: React.FC = () => {
  const [title, setTitle] = useState<string | undefined>(undefined);
  const [description, setDescription] = useState<string | undefined>(undefined);
  const [background, setBackground] = useState<boolean>(true);
  const [header, setHeader] = useState<boolean>(false);
  const [sidebar, setSidebar] = useState<boolean>(false);
  const [topRight, setTopRight] = useState<boolean>(false);
  const { loading, setLoading } = useLoading();

  useEffect(() => {
    setLoading(true);
    const handleLoad = () => setTimeout(() => setLoading(false), 1000);
    document.readyState === "complete" ? handleLoad() : window.addEventListener("load", handleLoad);
    return () => window.removeEventListener("load", handleLoad);
  }, [setLoading]);

  if (loading) return <pages.Loading />;

  return (
    <>
      <Helmet defer={false}>
        <title>{title || "Chocolet"}</title>
        <meta name="description" content={description || "The first ever chocolate-themed Blooket private server with mini-games, custom packs, and more, written in TypeScript by alicialol."} />
      </Helmet>
      <Background />
      <Routes>
        {Object.values(routes).map((route: RouteType) => (
          <Route
            key={route.path}
            path={route.path}
            element={
              <RouteWrapper
                title={title}
                description={description}
                background={background}
                header={header}
                sidebar={sidebar}
                topRight={topRight}
                element={route.element}
                plain={route.plain}
                setTitle={setTitle}
                setDescription={setDescription}
                setBackground={setBackground}
                setHeader={setHeader}
                setSidebar={setSidebar}
                setTopRight={setTopRight}
              />
            }
          />
        ))}
      </Routes>
    </>
  );
};

export default App;
