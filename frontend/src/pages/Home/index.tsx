import { Link } from "react-router-dom";

import styles from "./home.module.scss";

import { TransparentButton, BigButton } from "@components/index";

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
                    <div className={styles.welcomeDescription}>{import.meta.env.VITE_DESCRIPTION}</div>
                    <div className={styles.welcomeButtonContainer}>
			            <TransparentButton to="/register" children={"Register"} />
                        <TransparentButton to="https://discord.gg/VHvynmJHpR" children={"Discord"} />
                    </div>
                </div>
                <div className={styles.topButtonContainer}>
                    <BigButton width={"18vh"} height={"6vh"} lineHeight={"6vh"} fontSize={"3.6vh"} marginRight={"2.5vw"} to="/login" children={"Login"} />
                    <BigButton width={"25vh"} height={"8vh"} lineHeight={"8vh"} fontSize={"4.4vh"} to="/register" children={"Register"} />
                </div>
                <div className={styles.versionInfo}>Running {import.meta.env.VITE_NAME} v{import.meta.env.VITE_VERSION}</div>
                <div className={styles.tosLink}><Link to="/terms" className={styles.tosText}>Terms of Service</Link></div>
            </div>
        </>
    )
}
