import { Link } from "react-router-dom";

import styles from "./headerbar.module.scss";

export default function HeaderBar() {
    return (
	<div className={styles.headerBar}><Link className={styles.logoText} to="/">{import.meta.env.VITE_NAME}</Link></div>
    )
}
