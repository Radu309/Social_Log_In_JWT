import GoogleLogin, {GoogleLogout} from "react-google-login";

const clientId = "218049732892-biibgbig5rri4nrgm4v9kelj0fff8nkv.apps.googleusercontent.com";

function LogOut(){
    const onSuccess = () => {
        console.log("LOGOUT SUCCESS!");
    }
    return(
        <div id="signInButton">
            <GoogleLogout clientId={clientId}
                         buttonText="LogOut"
                         onSuccess={onSuccess}
            />
        </div>
    )
}
export default LogOut;
