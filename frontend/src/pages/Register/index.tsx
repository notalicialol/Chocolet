import { AuthButton, HeaderBar, HeaderBody, Input, InputModal } from "@components/index";

export default function Register() {
    return (
        <>
            <HeaderBar to="/login" innerText="Login" />
            <HeaderBody>
                <InputModal heading="Register">
                    <Input icon="fas fa-user" type="text" placeholder="Username" maxLength={16} />
                    <Input icon="fas fa-lock" type="password" placeholder="Password" maxLength={25} />
		    <Input icon="fas fa-key" type="password" placeholder="Access Code" />
                    <AuthButton buttonText="Let's Go!" />
                </InputModal>
            </HeaderBody>
        </>
    )
}
