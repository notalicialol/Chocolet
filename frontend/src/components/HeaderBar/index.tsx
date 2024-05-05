import { Link } from "react-router-dom";

import styles from "./headerbar.module.scss";

interface HeaderBarProps {
    to?: string;
    innerText?: string;
}

export default function HeaderBar({ to, innerText } : HeaderBarProps) {
    return (
	<div className={styles.headerBar}><Link className={styles.logoText} to="/">{import.meta.env.VITE_NAME}</Link>{to && <Link className={styles.rightLink} to={to}>{innerText}</Link>}</div>
    )
}
