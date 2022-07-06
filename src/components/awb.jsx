import {Page} from '@shopify/polaris'
import withAuth from "../components/withAuth";
import FulfilledOrders from './fulfilledOrders';


const AWB =()=>{
    return (
        <Page>
            <FulfilledOrders></FulfilledOrders>
        </Page>
    )
}

export default  withAuth(AWB);