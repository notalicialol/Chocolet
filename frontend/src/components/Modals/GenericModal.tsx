import styles from "./modals.module.scss";

interface GenericModalProps {
    heading: string;
    description: string;
}

export default function GenericModal({ heading, description } : GenericModalProps) {
    return (
        <div className={styles.genericContainer}>
            <div className={styles.genericHeader}>{heading}</div>
            <div className={styles.genericDescription}>{description}</div>
        </div>
    )
}