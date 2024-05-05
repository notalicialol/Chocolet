import { AuthButton, HeaderBar, HeaderBody, Input, InputModal } from "@components/index";

export default function Login() {
    return (
        <>
            <HeaderBar to="/register" innerText="Register" />
            <HeaderBody>
                <InputModal heading="Login">
                    <Input icon="fas fa-user" type="text" placeholder="Username" maxLength={16} />
                    <Input icon="fas fa-lock" type="password" placeholder="Password" maxLength={25} />
                    <AuthButton buttonText="Let's Go!" />
                </InputModal>
            </HeaderBody>
        </>
    )
}
