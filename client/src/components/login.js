import GoogleLogin from "react-google-login";

const clientId = "218049732892-biibgbig5rri4nrgm4v9kelj0fff8nkv.apps.googleusercontent.com";

function Login(){
    const onSuccess = (res) => {
        console.log("LOGIN SUCCESS! Current user: ", res.profileObj);
    }
    const onFailure = (res) => {
        console.log("LOGIN FAILED! Current res: ", res);
    }
    return(
        <div id="signInButton">
            <GoogleLogin clientId={clientId}
                         buttonText="LogIn"
                         onSuccess={onSuccess}
                         onFailure={onFailure}
                         cookiePolicy={"single_host_origin"}
                         isSignedIn={true}
            />
        </div>
    )
}
export default Login;