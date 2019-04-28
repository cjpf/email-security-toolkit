import React, { Component } from 'react';
import './App.css';

import DKIMVerify from './dkim-verify';

export default class App extends Component {
    constructor(props) {
        super(props);

        this.state = { rawEmail:'' };
        this.handleFormChange = this.handleFormChange.bind(this);
        this.dkimVerify = this.dkimVerify.bind(this);
    }

    handleFormChange(event) {
        const target = event.target;
        const value = target.value;
        const name = target.name;
        this.setState({ [name] : value });
    }

    dkimVerify() {
        let verification = new DKIMVerify(this.state.rawEmail);
        alert(verification.signingAlgo);
        return;
    }

    render() {
        return (
            <div className="App">
                <textarea placeholder="Full raw email (copy/paste)."
                 onChange={(e)=>{this.handleFormChange(e);}} name="rawEmail" id="rawEmail" />
                <br />
                <input type="button" value="Check" onClick={()=>{this.dkimVerify();}} />
            </div>
        );
    }
};
