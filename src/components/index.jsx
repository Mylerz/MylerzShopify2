import { Page } from '@shopify/polaris'
import OrdersList from '../components/ordersList';
import WithAuth from "../components/withAuth";

function Index() {
    return (
        <Page>
            <OrdersList></OrdersList>
        </Page>

    );
}

export default WithAuth(Index);
