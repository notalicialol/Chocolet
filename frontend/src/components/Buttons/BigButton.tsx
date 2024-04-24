import { Link } from "react-router-dom";

import styles from "./buttons.module.scss";

interface BigButtonProps {
    to: string;
    style?: React.CSSProperties;
    marginRight?: string | number;
    width?: string | number;
    height?: string | number;
    lineHeight?: string | number;
    backgroundColor?: string;
    fontSize?: string | number;
    children: React.ReactNode;
}

export default function BigButton({ to, marginRight, width, height, lineHeight, fontSize, children }: BigButtonProps) {
    const customCSS = {
        marginRight,
        lineHeight,
        height,
        width,
        fontSize
    };

    return (
        <div className={styles.big} style={customCSS}><Link to={to}>{children}</Link></div>
    );
}
