import {
  Provider as AppBridgeProvider,
} from "@shopify/app-bridge-react";
import { authenticatedFetch } from "@shopify/app-bridge-utils";
import { Redirect } from "@shopify/app-bridge/actions";
import { AppProvider as PolarisProvider } from "@shopify/polaris";
import translations from "@shopify/polaris/locales/en.json";
import "@shopify/polaris/build/esm/styles.css";

import Index from "./components/index";
import Login from "./components/login";
import FulfilledOrders from "./components/fulfilledOrders";
import AWB from "./components/awb";
import warehouseContext from "./components/warehouseContext"
import Order from "./components/order"


import { Routes, Route, BrowserRouter } from 'react-router-dom';
import { useState } from "react";
import PrintPDF from "./components/pdf";


export default function App() {

  const [orderItemWarehouse, setOrderItemWarehouse] = useState([]);
  const [warehouseOptions, setWarehouseOptions] = useState([]);


  const updateOrderItemWarehouseFunction = (orderItemWarehouseList) => {
    // this.setState((state) => {
    let newOrderItemWarehouseList = [...orderItemWarehouse];
    orderItemWarehouseList.forEach(orderItemWarehouse => {
      newOrderItemWarehouseList.find(row => (row.orderId == orderItemWarehouse.orderId) && (row.itemId == orderItemWarehouse.itemId)) ?
        newOrderItemWarehouseList.find(row => (row.orderId == orderItemWarehouse.orderId) && (row.itemId == orderItemWarehouse.itemId)).warehouse = orderItemWarehouse.warehouse : newOrderItemWarehouseList.push(orderItemWarehouse)

    })
    console.log("newOrderItemWarehouseList from _app", newOrderItemWarehouseList);
    setOrderItemWarehouse(newOrderItemWarehouseList);
    // return { orderItemWarehouse: newOrderItemWarehouseList }
    // })

  }

  const setOrderItemWarehouseFunction = (orderItemWarehouse) => {
    setOrderItemWarehouse(orderItemWarehouse);
  }

  const updateWarehouseOptions = (warehouseOptions) => {
    console.log(`Updating warehouseOptions: ${warehouseOptions}`)
    setWarehouseOptions(warehouseOptions);
  }

  return (
    <AppBridgeProvider
      config={{
        apiKey: process.env.SHOPIFY_API_KEY,
        host: new URL(location).searchParams.get("host"),
        forceRedirect: true,
      }}>
      <PolarisProvider i18n={translations}>

        <warehouseContext.Provider value={{ warehouseOptions: warehouseOptions, updateWarehouseOptions: updateWarehouseOptions, orderItemWarehouse: orderItemWarehouse, updateOrderItemWarehouse: updateOrderItemWarehouseFunction, setOrderItemWarehouse: setOrderItemWarehouseFunction }}>
          <BrowserRouter>

            <Routes>
              <Route path="/" element={<Index />} />
              <Route path="/login" element={<Login />} />
              <Route path="/awb" element={<AWB />} />
              <Route path="/order/:id" element={<Order />} />
              <Route path="/pdf" element={<PrintPDF />} />
            </Routes>
          </BrowserRouter>
        </warehouseContext.Provider>
      </PolarisProvider >
    </AppBridgeProvider>

  );
}

// function MyProvider({ children }) {
//   const app = useAppBridge();

//   const client = new ApolloClient({
//     cache: new InMemoryCache(),
//     link: new HttpLink({
//       credentials: "include",
//       fetch: userLoggedInFetch(app),
//     }),
//   });

//   return <ApolloProvider client={client}>{children}</ApolloProvider>;
// }

export function userLoggedInFetch(app) {
  const fetchFunction = authenticatedFetch(app);

  return async (uri, options) => {
    const response = await fetchFunction(uri, options);

    if (
      response.headers.get("X-Shopify-API-Request-Failure-Reauthorize") === "1"
    ) {
      const authUrlHeader = response.headers.get(
        "X-Shopify-API-Request-Failure-Reauthorize-Url"
      );

      const redirect = Redirect.create(app);
      redirect.dispatch(Redirect.Action.APP, authUrlHeader || `/auth`);
      return null;
    }

    return response;
  };
}
