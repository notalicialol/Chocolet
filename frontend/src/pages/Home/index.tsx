import { Link } from "react-router-dom";
import { Tooltip } from "react-tooltip";

import styles from "./home.module.scss";

import { TransparentButton, BigButton } from "@components/index";

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
                    <div className={styles.welcomeSocials}>
                        <a href="https://github.com/notalicialol/Chocolet" target="_blank"><i className={"fa-brands fa-github " + styles.welcomeSocialIcon} data-tooltip-id="githubTip" data-tooltip-content="Github" data-tooltip-place="bottom" /></a>
                        <Tooltip id="githubTip" />
                        <a href="https://youtube.com/@notalicialol" target="_blank"><i className={"fa-brands fa-youtube " + styles.welcomeSocialIcon} data-tooltip-id="youtubeTip" data-tooltip-content="YouTube" data-tooltip-place="bottom" /></a>
                        <Tooltip id="youtubeTip" />
                        <a href="https://twitter.com/@notalicialol" target="_blank"><i className={"fa-brands fa-x-twitter " + styles.welcomeSocialIcon + " " + styles.welcomeSocialRight} data-tooltip-id="xTip" data-tooltip-content="X" data-tooltip-place="bottom" /></a>
                        <Tooltip id="xTip" />
                    </div>
                </div>
                <div className={styles.topButtonContainer}>
                    <BigButton width={"18vh"} height={"6vh"} lineHeight={"6vh"} fontSize={"3.6vh"} marginRight={"2.5vw"} to="/login" children={"Login"} />
                    <BigButton width={"25vh"} height={"8vh"} lineHeight={"8vh"} fontSize={"4.4vh"} to="/register" children={"Register"} />
                </div>
		    <div className={styles.termsRequired}>By using this site you automatically agree to our Terms of Service.</div>
		    <div className={styles.copyrightText}>{import.meta.env.VITE_NAME} © 2024 All Rights Reserved.</div>
            <div className={styles.versionInfo}>Running {import.meta.env.VITE_NAME} v{import.meta.env.VITE_VERSION}</div>
                <div className={styles.tosLink}><Link to="/terms" className={styles.tosText}>Terms of Service</Link></div>
            </div>
        </>
    )
}
