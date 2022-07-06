import { InlineError, Form, FormLayout, Button, TextField, Page, Layout, Card, } from '@shopify/polaris'
import { useState } from "react";
// import Cookies from 'js-cookie';
// import { Router } from 'react-router-dom';
// import Router from 'next/router'
import { useNavigate } from '@shopify/app-bridge-react';
import { userLoggedInFetch } from "../App";
import { useAppBridge } from "@shopify/app-bridge-react";

import { db } from '../db'
//localForage.setDriver(localForage.INDEXEDDB);


function Login() {
    const [userName, setUserName] = useState('');
    const [password, setPassword] = useState('');
    const [isWrongCredential, setIsWrongCredential] = useState(false);
    const navigate = useNavigate()
    const app = useAppBridge();
    const fetch = userLoggedInFetch(app);

    const handleUserNameChanged = async (value) => setUserName(value);
    const handlePasswordChanged = value => setPassword(value);

    const handleSubmit = async (e) => {
        try {


            let data = {
                // "grant_type":"password",
                "username": userName,
                "password": password
            }


            let response = await fetch(`/api/login`, {
                headers: {
                    'Content-Type': 'application/json',
                },
                method: 'POST',
                body: JSON.stringify(data)
            })

            let result = await response.json()

            if (result.status === 'success') {
                localStorage.setItem("access_token", result.data.access_token);
                navigate("/")
            }
            else
                setIsWrongCredential(true)

        } catch (error) {

            console.log(error);

        }

    }




    return (
        <Page>
            <Layout>
                <Layout.Section fullWidth>


                    <Layout.AnnotatedSection
                        title="Mylerz Login Credentials"
                    >
                        <Card sectioned>
                            <Form onSubmit={handleSubmit}>
                                <FormLayout>
                                    <TextField
                                        value={userName}
                                        onChange={handleUserNameChanged}
                                        label="UserName"
                                        type="text"
                                        placeholder="username"
                                    />
                                    <TextField
                                        value={password}
                                        onChange={handlePasswordChanged}
                                        label="Password"
                                        type="password"
                                        placeholder="password"
                                    />
                                    <Button submit>Login</Button>
                                </FormLayout>
                            </Form>
                        </Card>
                    </Layout.AnnotatedSection>
                </Layout.Section>
            </Layout>
            {isWrongCredential ? (
                <InlineError message="Wrong Username Or Password" />
            ) : (<div></div>)}
        </Page>
    );
}


export default Login;
