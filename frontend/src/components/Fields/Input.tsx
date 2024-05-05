import { useState } from "react";
import styles from "./input.module.scss";

interface InputProps {
    icon?: string,
    type: string,
    name?: string,
    placeholder: string,
    maxLength?: number,
    onChange?: (event: React.ChangeEvent<HTMLInputElement>) => void
}

export default function Input({icon, type, name, placeholder, maxLength, onChange} : InputProps) {
    const [focused, setFocused] = useState(false);

    return (
        <div className={`${styles.inputContainer} ${focused ? styles.inputFocused : ""}`}>
            {icon && <i className={`${icon} ${styles.inputIcon} ${focused ? styles.iconFocused : ""}`} />}
            <input className={styles.formInput} type={type} name={name} placeholder={placeholder} spellCheck="false" autoComplete="username" maxLength={maxLength} onChange={onChange} onFocus={() => setFocused(true)} onBlur={() => setFocused(false)}></input>
        </div>
    )
}