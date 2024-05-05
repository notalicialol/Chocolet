import styles from "./buttons.module.scss";

interface AuthButtonProps {
    buttonText: string
}

export default function AuthButton({ buttonText } : AuthButtonProps) {
    return (
        <button className={styles.auth} tabIndex={0} type="submit">{buttonText}</button>
    )
}