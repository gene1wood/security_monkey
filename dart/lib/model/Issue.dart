library security_monkey.model_issue;

import 'Item.dart';
import 'package:security_monkey/util/utils.dart' show localDateFromAPIDate;

class Issue {
    int id;
    int score;
    String issue;
    String notes;
    bool justified;
    String justified_user;
    String justification;
    //String justified_date;
    DateTime justified_date;
    int item_id;
    bool selected_for_justification;

    Item item;

    Issue.fromMap(Map data) {
        id = data['id'];
        score = data['score'];
        issue = data['issue'];
        notes = data['notes'];
        justified = data['justified'];
        justified_user = data['justified_user'];
        justification = data['justification'];
        if (data['justified_date'] != null) {
            justified_date = localDateFromAPIDate(data['justified_date']);
        }
        item_id = data['item_id'];
        selected_for_justification = false;

        item = new Item.fromMap({
            "item": data
        });


    }
}
