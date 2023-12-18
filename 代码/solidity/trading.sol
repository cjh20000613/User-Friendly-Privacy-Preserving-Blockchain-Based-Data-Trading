// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

contract Trading{

    //////////////////////////////////////////////////////////
    /// error                                        /////////
    //////////////////////////////////////////////////////////
    error Trading__NotDataBroker();
    error Trading__NotContract();
    error Trading__Rejoin();
    error Trading__NotDataOwner();
    error Trading__TXLock();
    error Trading__DONumberIsZero();
    error Trading__NotNewDataOwner();
    error Trading__NotNewDataConsumer();
    error Trading__WrongData();
    error Trading__NotDataConsumer();
    error Trading__IncorrectDataOwner();
    error Trading__CanNotSimpleChange();

    ////////////////////////////////////////////////////////
    /// 状态变量                                   //////////
    ////////////////////////////////////////////////////////
    
    //合约创建者
    address private immutable owner;
    //中介费
    uint256 private immutable Fee;
    //隐私补偿费
    uint256 private immutable fee;
    //数据位数
    uint256 public immutable digit;

    //数据拥有者参与队列
    address[] public DO_addr;
    //参与队列位置
    uint256 private DO_site;

    //数据拥有者地址数组
    address[] private DO_join_addr;

    //交易队列
    address[] private DC_addr;
    //交易队列位置
    uint256 private DC_site;
    //交易锁
    uint8 private tx_lock;


    ////////////////////////////////////////////////////////
    /// 结构体                                    //////////
    ////////////////////////////////////////////////////////
    
    //数据拥有者
    struct DataOwner
    {
        address ownerAddr;      //数据所有者的地址
        uint256 value;          //数据价值
        uint256[] privacy;      //隐私预算（x*100）
        uint256 length;         //数据条数
        uint256[2] tao;         //安全范围 ((x+1)*10)
        string CID;             //IPFS哈希
        string ek;              //加密后的对称密钥
        uint256 release;        //可以提出的钱
        uint256 site;           //位置
        bool join;              //是否加入
        uint256[] change;       //是否可以改变
        string[] introduction;  //数据介绍
    }

    //数据消费者
    struct DataConsumer
    {
        address ownerAddr;      //数据消费者地址
        uint256 budget;         //预算
        uint256 privacy;        //隐私预算
        uint256 times;          //参与次数
        string request;         //查询请求
        string es;              //查询结果
        bool join;              //是否加入
    }

    //////////////////////////////////////////////////////////
    /// 映射                                        //////////
    //////////////////////////////////////////////////////////
    
    //记录对应地址的数据拥有者信息
    mapping(address => mapping(uint8 => DataOwner)) public DataOwner_info;
    //记录对应地址的数据消费者信息
    mapping(address => DataConsumer) public DataConsumer_info;

    //////////////////////////////////////////////////////////
    /// 事件                                        //////////
    //////////////////////////////////////////////////////////

    event DOJoin(uint256 indexed value, uint256[] indexed privacy, uint256[2] indexed tao, uint8 i);
    event DOUpdate(uint256 indexed privacy, uint256 indexed site);
    event DCPurchase(uint256 indexed budget, uint256 indexed privacy, string request);
    event DBUpdateDO(uint256 indexed site, uint256[] indexed change, string[] introduction);
    event DBDeleteDO(uint256 indexed site, uint8 i);
    event TXGenerate(address indexed DataConsumer, uint256 indexed DC_budget, uint256 indexed privacy, string request);
    event TXProcess(address indexed DataConsumer, uint256 indexed num, uint256 indexed releaseBudget, uint256[] choose, address[] DO, uint256 fee);

    /////////////////////////////////////////////////////////
    /// 修饰器                                      /////////
    /////////////////////////////////////////////////////////

    modifier onlyDB(){
        if(msg.sender != owner){
            revert Trading__NotDataBroker();
        }
        _;
    }

    modifier onlyDC(){
        if(DataConsumer_info[msg.sender].times == 0){
            revert Trading__NotDataConsumer();
        }
        _;
    }

    //交易的参与者必须是用户类型而不能是合约
    modifier notContract(){
        if(msg.sender != tx.origin){
            revert Trading__NotContract();
        }
        _;
    }

    //不能是数据经纪人或正在交易的数据购买者
    modifier notRejoin(){
        if(_rejoin(msg.sender) == true){
            revert Trading__Rejoin();
        }
        _;
    }

    modifier txLock(){
        if(tx_lock == 1){
            revert Trading__TXLock();
        }
        _;
    }

    ////////////////////////////////////////////////////////
    /// 函数                                        ////////
    ////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////
/// 构造函数

    constructor(uint256 _fee)
    {
        owner = msg.sender;
        Fee = _fee;                     //0.5eth
        fee = _fee;                     //0.5eth
        digit = _fee / 50;             //0.01eth
    }

//////////////////////////////////////////////////////////////////////////////
/// 数据拥有者

    //数据拥有者申请加入(隐私预算*100)
    function dataOwner_Join(uint256 _value, string calldata _cid, string memory _ek, uint256[] memory _privacy, uint256[2] memory _tao) public notContract notRejoin returns(uint8 i){
        DO_addr.push(msg.sender);
        for(;DataOwner_info[msg.sender][i].join == true;i++){}
        if(i >= 2){
            revert Trading__IncorrectDataOwner();
        }
        uint256 length = _privacy.length;
        DataOwner_info[msg.sender][i].ownerAddr = msg.sender;
        DataOwner_info[msg.sender][i].value = _value;
        DataOwner_info[msg.sender][i].privacy = _privacy;
        DataOwner_info[msg.sender][i].length = length;
        DataOwner_info[msg.sender][i].tao = _tao;
        DataOwner_info[msg.sender][i].CID = _cid;
        DataOwner_info[msg.sender][i].ek = _ek;
        DataOwner_info[msg.sender][i].site = DO_addr.length - 1;
        DataOwner_info[msg.sender][i].join = true;
        emit DOJoin(_value, _privacy, _tao, i);
        return i;
    }

    //数据拥有者提钱
    function dataOwner_Withdraw() public payable{
        uint256 balance;
        for(uint8 i; i < 3; i++){
            uint256 tempBalance;
            tempBalance = DataOwner_info[msg.sender][i].release;
            if(tempBalance > 0){
                DataOwner_info[msg.sender][i].release = 0;
                balance += tempBalance;
            }
        }
        payable(msg.sender).transfer(balance);
    }

    //数据拥有者更新请求
    function dataOwner_Update(uint256 _privacy, uint256 _j) public{
        uint8 i;
        for(;DataOwner_info[msg.sender][i].join == false && i<3;i++){}
        if(i == 3){
            revert Trading__IncorrectDataOwner();
        }
        if(DataOwner_info[msg.sender][i].change[_j] == 0){
            revert Trading__CanNotSimpleChange();
        }
        DataOwner_info[msg.sender][i].privacy[_j] += _privacy;
    }

////////////////////////////////////////////////////////////////////////
//// 数据消费者

    //数据消费者发出购买请求(隐私预算*100)
    function dataConsumer_Purchase(uint256 _privacy, string memory _request) public payable notContract notRejoin{
        uint256 times = DataConsumer_info[msg.sender].times + 1; 
        DC_addr.push(msg.sender);
        DataConsumer_info[msg.sender].ownerAddr = msg.sender;
        DataConsumer_info[msg.sender].budget = msg.value;
        DataConsumer_info[msg.sender].privacy = _privacy;
        DataConsumer_info[msg.sender].times = times;
        DataConsumer_info[msg.sender].request = _request;
        DataConsumer_info[msg.sender].join = true;
        emit DCPurchase(msg.value, _privacy, _request);
    }

    function dataConsumer_Result() public view onlyDC returns (string memory){
        return DataConsumer_info[msg.sender].es;
    }

///////////////////////////////////////////////////////////////////////
//// 数据经济人

    //下载并检查数据拥有者提交的数据
    function DO_data() public onlyDB txLock returns(uint256 site_, string memory cid_,string memory ek_, uint256 value_, uint256[] memory privacy_, uint256 length_, uint256[2] memory tao_) {
        if(DO_site == DO_addr.length){
            revert Trading__NotNewDataOwner();
        }
        address do_addr = DO_addr[DO_site];
        uint8 i;
        for(;DataOwner_info[do_addr][i].join == false && i<3;i++){}
        if(i == 3){
            revert Trading__IncorrectDataOwner();
        }
        cid_ = DataOwner_info[do_addr][i].CID;
        ek_ = DataOwner_info[do_addr][i].ek;
        value_ = DataOwner_info[do_addr][i].value;
        privacy_ = DataOwner_info[do_addr][i].privacy;
        length_ = DataOwner_info[do_addr][i].length;
        tao_ = DataOwner_info[do_addr][i].tao;
        site_ = DO_site;
        DO_site++;
        _addAddress(do_addr);
        return(site_, cid_, ek_, value_, privacy_, length_, tao_);
    }

    //更新数据拥有者信息
    function update_DO(uint256 _site, uint8 _i, uint256[] memory _change, string[] memory _introduction) public onlyDB txLock {
        address do_addr = DO_addr[_site];
        if(DataOwner_info[do_addr][_i].join == false){
            revert Trading__IncorrectDataOwner();
        }
        if(_change.length != DataOwner_info[do_addr][_i].length || _introduction.length != DataOwner_info[do_addr][_i].length){
            revert Trading__WrongData();
        }
        DataOwner_info[do_addr][_i].change = _change;
        DataOwner_info[do_addr][_i].introduction = _introduction;
        emit DBUpdateDO(_site, _change, _introduction);
    }

    //删除有问题的数据拥有者
    function delete_DO(uint256 _site, uint8 _i) public onlyDB txLock {
        address do_addr = DO_addr[_site];
        if(DataOwner_info[do_addr][_i].join == false){
            revert Trading__IncorrectDataOwner();
        }
        DataOwner_info[do_addr][_i].join = false;
        uint8 i;
        for(;DataOwner_info[do_addr][i].join == false && i<3;i++){}
        if(i >= 3){
            _removeAddress(do_addr);
        }
        emit DBDeleteDO(_site, _i);
    }

    //生成交易
    function tx_generate() public onlyDB returns (uint256 budget_, uint256 privacy_, string memory request_, address[] memory DO_){
        if(DC_site == DC_addr.length){
            revert Trading__NotNewDataConsumer();
        }
        tx_lock = 1;
        address addr = DC_addr[DC_site];
        budget_ = DataConsumer_info[addr].budget;
        privacy_ = DataConsumer_info[addr].privacy;
        request_ = DataConsumer_info[addr].request;
        DO_ = DO_join_addr;
        emit TXGenerate(addr, budget_, privacy_, request_);
        return(budget_, privacy_, request_, DO_);
    }

    //完成交易(买不到数据退钱或者提交结果)
    function tx_process(string memory _es, uint256[] memory _choose, uint256 _num, uint256 _budget, uint256 _fee) public onlyDB {
        if(_choose.length != DO_join_addr.length){
            revert Trading__WrongData();
        }
        tx_lock = 0;
        address addr = DC_addr[DC_site];
        DC_site++;
        if(_num == 0){
            DataConsumer_info[addr].join = false;
            uint256 balance = DataConsumer_info[addr].budget;
            payable(addr).transfer(balance);
        }else {
            DataConsumer_info[addr].join = false;
            DataConsumer_info[addr].es = _es;
            payable(addr).transfer(_budget);
            _release(_choose,_fee);
        }
        address[] memory DO_ = DO_join_addr;
        emit TXProcess(addr, _num, _budget, _choose, DO_, _fee);
    }

    function getDOnumber() public view returns(uint256){
        return DO_join_addr.length;
    }

///////////////////////////////////////////////////////////////////////
/// 内部函数

    //检查是否已经加入过或存在其他身份
    function _rejoin(address _user) internal view returns (bool) {
        //是数据经纪人
        if(_user == owner){
            return true;
        }
        //是数据消费者且上传交易未完成
        if(DataConsumer_info[_user].times > 0){
            if(DataConsumer_info[_user].join == true){
                return true;
            }
        }
        return false;
    }

    //分钱
    function _release(uint256[] memory _choose, uint256 _fee) internal{
        address addr;
        uint256 value_sum = _valueSum();
        for(uint i=0; i < _choose.length; i++){
            addr = DO_join_addr[i];
            uint8 j;
            for(;DataOwner_info[addr][j].join == false && i<3;j++){}
            uint256 temp_value = DataOwner_info[addr][j].value;
            if(_choose[i] == 1){
                DataOwner_info[addr][j].release += temp_value;
            }
            uint256 privacy_value = _fee * temp_value / value_sum;
            DataOwner_info[addr][j].release += privacy_value;
        }
    }

    //数据价值和
    function _valueSum() internal view returns (uint256 value_) {
        address addr;
        for(uint256 i=0; i < DO_join_addr.length; i++){
            addr = DO_join_addr[i];
            for(uint8 j;DataOwner_info[addr][j].join == true;j++){
                value_ += DataOwner_info[addr][j].value;
            }
        }
        return value_;
    }

    function _addAddress(address newAddress) internal{
        if(_addressExists(newAddress) == false){
            DO_join_addr.push(newAddress);
        }
    }

    function _addressExists(address checkAddress) internal view returns (bool) {
        for (uint256 i = 0; i < DO_join_addr.length; i++) {
            if (DO_join_addr[i] == checkAddress) {
                return true;
            }
        }
        return false;
    }

    function _removeAddress(address addressToRemove) internal {
        // 获取要删除的地址在数组中的索引
        uint256 indexToRemove = _getAddressIndex(addressToRemove);

        // 将要删除的地址与数组中的最后一个地址进行交换
        DO_join_addr[indexToRemove] = DO_join_addr[DO_join_addr.length - 1];

        // 删除数组中的最后一个元素
        DO_join_addr.pop();
    }

    function _getAddressIndex(address checkAddress) internal view returns (uint256) {
        for (uint256 i = 0; i < DO_join_addr.length; i++) {
            if (DO_join_addr[i] == checkAddress) {
                return i;
            }
        }
        revert("Address not found");
    }

}