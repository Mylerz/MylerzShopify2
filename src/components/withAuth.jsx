import React, { Component, createContext, useState, useContext, useEffect, useLayoutEffect } from 'react'
// import Router from 'next/router'
import { userLoggedInFetch } from "../App";
import { useAppBridge, useNavigate } from "@shopify/app-bridge-react";
// import React, { createContext, useState, useContext, useEffect, useLayoutEffect } from 'react'
// import TokenContext from '../context/TokenContext'
// import { getCookie } from '../utils/Cookies'
// import Cookies from "js-cookie";
import { db } from '../db'
//localForage.setDriver(localForage.INDEXEDDB);


const WithAuth = (AuthComponent) => {
  return (props) => {
    const [isLoading, setIsLoading] = useState(true);
    let navigate = useNavigate();

    const app = useAppBridge();
    const fetch = userLoggedInFetch(app);
    useEffect(() => {
      let authenticate = async () => {
        try {

          let token = localStorage.getItem("access_token");

          let response = await fetch("api/warehouses", {
            method: "POST",
            headers: {
              "content-type": "application/json",
            },
            body: JSON.stringify({
              token: token,
            }),
          });

          let result = await response.json();
          console.log(result);

          if (result.Error == "Authorization has been denied for this request.") {
            navigate('/login');
          } else {
            setIsLoading(false)
          }
        } catch (error) {
          navigate('/login');
        }
      }
      authenticate()
      // setIsLoading(false)
      // Router.push('/login')          

    }, [])


    return (<div>
      {isLoading ? (
        <div>LOADING....</div>
      ) : (
        //   <TokenContext.Provider value={this.props.token}>
        <AuthComponent {...props} />
        //   </TokenContext.Provider>
      )}
    </div>)

  }

};

export default WithAuth;