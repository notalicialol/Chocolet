import { Link } from "react-router-dom";

import styles from "./buttons.module.scss";

interface TransparentButtonProps {
    to: string;
    children: React.ReactNode;
}

export default function TransparentButton({ to, children }: TransparentButtonProps) {
    return (
        <Link className={styles.transparent} to={to}>{children}</Link>
    );
}
