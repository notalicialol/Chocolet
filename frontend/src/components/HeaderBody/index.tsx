import styles from "./headerbody.module.scss";

interface HeaderBodyProps {
    children: React.ReactNode;
}

export default function HeaderBody({ children } : HeaderBodyProps) {
    return (
        <div className={styles.content}>{children}</div>
    )
}