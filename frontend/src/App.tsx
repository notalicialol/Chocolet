import { createBrowserRouter, RouterProvider, Outlet } from "react-router-dom";

import "./all.scss";

import { Background } from "@components/index";

const router = createBrowserRouter([{
    id: "app",
    errorElement: <h1>An unexpected error has occurred.</h1>,
    element:
    <>
        <Background />

        <Outlet/>
    </> ,
    children: [
        { id: "home", path: "/", element: <></> }
    ]
}]);

export default function App() {
    return <RouterProvider router={router} />;
}