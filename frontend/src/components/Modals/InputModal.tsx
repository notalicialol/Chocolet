import styles from "./modals.module.scss";

interface InputModalProps {
    heading: string;
    children: React.ReactNode;
}

export default function GenericModal({ heading, children } : InputModalProps) {
    return (
        <div className={styles.genericContainer}>
            <div className={styles.inputHeader}>{heading}</div>
            {children}
        </div>
    )
}