import { Link } from "react-router-dom";

import styles from "./home.module.scss";

/* to-do: make button components tomorrow to simplify code and fix version management
    rewrite the scss so the appearance is more appealing, fix colors
    just fix the text too
*/

export default function Home() {
    return (
        <>
            <div className={styles.container}>
                <img src="/content/HomeBlooks.png" className={styles.homeBlookImage}/>
                <div className={styles.headerSide}></div>
                <div className={styles.topHeaderContainer}>
                    <div className={styles.logoText}>{import.meta.env.VITE_NAME}</div>
                </div>
                <div className={styles.welcomeContainer}>
                    <div className={styles.welcomeText}>
                        Blooket
                        <br />
                        Private
                        <br />
                        Server
                    </div>
                    <div className={styles.welcomeDesc}>{import.meta.env.VITE_DESCRIPTION}</div>
                    <div className={styles.welcomeButtonContainer}>
                        <Link className={styles.welcomeButton} to="/register">Register</Link>
                        <Link className={styles.welcomeButton} to="https://discord.gg/VHvynmJHpR" target="_blank">Discord</Link>
                    </div>
                </div>
                <div className={styles.topButtonContainer}>
                    <div className={styles.topButton + " " + styles.loginButton}><Link to="/login">Login</Link></div>
                    <div className={styles.topButton + " " + styles.signupButton}><Link to="/register">Register</Link></div>
                </div>
                <div className={styles.versionInfo}>Running {import.meta.env.VITE_NAME} v{import.meta.env.VITE_VERSION}</div>
                <div className={styles.tosLink}><Link to="/terms" className={styles.tosText}>Terms of Service</Link></div>
            </div>
        </>
    )
}