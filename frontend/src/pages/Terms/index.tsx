import { HeaderBar, HeaderBody  } from "@components/index";

import styles from "./terms.module.scss";

export default function Terms() {
    return (
        <>
	        <HeaderBar />
            <HeaderBody>
                <div className={styles.heading}>{import.meta.env.VITE_NAME} - Terms of Service</div>
                <div className={styles.subheading}>Revised 04/24/24</div>

                <div className={styles.termGroup}>
                    <div className={styles.termHeading}>Acceptance of Terms</div>
                    <div className={styles.termDescription}>By utilizing Chocolet, you consent to adhere to the terms of service outlined. Should you disagree with these terms, your account is subject to termination.</div>
                </div>

                <div className={styles.termGroup}>
                    <div className={styles.termHeading}>Modifications to Terms</div>
                    <div className={styles.termDescription}>Chocolet holds the authority to alter the terms of service whenever it chooses, without prior notification. By continuing to use the website following any updates, you are implicitly agreeing to the revised terms.</div>
                </div>

                <div className={styles.termGroup}>
                    <div className={styles.termHeading}>Usage of Website</div>
                    <div className={styles.termDescription}>You are permitted to use Chocolet solely for legal activities. It is prohibited to utilize the website in a manner that breaches any relevant laws or regulations.</div>
                </div>

                <div className={styles.termGroup}>
                    <div className={styles.termHeading}>Age Restriction</div>
                    <div className={styles.termDescription}>You must be at least 13 years of age to play Chocolet. By accessing the website, you affirm and guarantee that you are 13 years old or older.</div>
                </div>

                <div className={styles.termGroup}>
                    <div className={styles.termHeading}>Refunds</div>
                    <div className={styles.termDescription}>Chocolet does not offer refunds for any kind of reason.</div>
                </div>

                <div className={styles.termGroup}>
                    <div className={styles.termHeading}>Data Collection</div>
                    <div className={styles.termDescription}>Chocolet does not gather any personal information, except for a hashed version of your IP address. This information is not shared with external parties.</div>
                </div>

                <div className={styles.termGroup}>
                    <div className={styles.termHeading}>Termination of Accounts</div>
                    <div className={styles.termDescription}>Chocolet reserves the right to discontinue your access to the website immediately and without prior notice if you fail to comply with the terms of service.</div>
                </div>

                <div className={styles.termGroup}>
                    <div className={styles.termHeading}>Disclaimer of Warranties</div>
                    <div className={styles.termDescription}>Chocolet offers the website "as is" and "as available," without making any explicit or implied guarantees regarding its operation or the accuracy of the information, content, materials, or products featured on the website. By using the website, you acknowledge and accept that you do so entirely at your own risk.</div>
                </div>

                <div className={styles.termGroup}>
                    <div className={styles.termHeading}>Limitation of Liability</div>
                    <div className={styles.termDescription}>Chocolet will not be held responsible for any kind of damages, including but not limited to, loss of profits, disruption of business, loss of data or programs, or any financial loss resulting from the use or inability to use the website, or from any content, materials, products, or services provided through the website. This holds true even if Chocolet has been made aware of the potential for such damages. However, this limitation of liability may not be applicable to you if the laws of your state or jurisdiction do not permit the exclusion or limitation of liability for indirect or incidental damages.</div>
                </div>

                <div className={styles.termGroup}>
                    <div className={styles.termHeading}>Indemnification</div>
                    <div className={styles.termDescription}>You consent to protect, support, and absolve Chocolet, including its owners, administrators, moderators, helpers, testers, and members, from all forms of losses, costs, damages, and expenses, including fees for legal representation, that arise due to any breach of these terms of service by you or anyone else using the website.</div>
                </div>

                <div className={styles.termGroup}>
                    <div className={styles.termHeading}>Account Compromises</div>
                    <div className={styles.termDescription}>At Chocolet, we prioritize the security and confidentiality of our users' information. Unauthorized access, usage, or compromise of another user's account is strictly forbidden. Should any user be found breaching this policy, we hold the authority to take necessary measures, including account suspension or termination, and we may report the matter to law enforcement agencies. We are committed to assisting in any investigations by providing required information, such as the implicated user's IP address, to support legal inquiries. We encourage our users to safeguard their account details and to promptly report any unusual activities to our team. By utilizing our service, you consent to adhere to our Terms of Service and all relevant legal provisions.</div>
                </div>

                <div className={styles.termGroup} style={{paddingBottom: "2vh"}}>
                    <div className={styles.termHeading}>Governing Law</div>
                    <div className={styles.termDescription}>These terms of service are subject to and interpreted following the laws of the United States of America, disregarding any conflict of law principles. You acknowledge that any legal or equitable claims associated with these terms must be initiated solely within the state or federal courts situated in the jurisdiction where Chocolet operates. By agreeing to these terms, you also consent to the jurisdiction of these courts to oversee any related legal proceedings.</div>
                </div>
            </HeaderBody>
        </>
    )
}
